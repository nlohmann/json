# Recipes for Common Types

The library converts the standard containers, strings, numbers, tuples, `std::optional`, and `std::filesystem::path`
(the last two since version 3.12.0, C++17) out of the box, and your own types once you write conversion functions or use
the macros (see [Arbitrary type conversions](arbitrary_types.md)). It deliberately does **not** convert smart pointers,
`std::variant`, `std::chrono` types, or class hierarchies, because there is more than one reasonable JSON
representation for each of them. This page shows a representation for each that you can copy and adapt.

All recipes use a specialization of [`adl_serializer`](../api/adl_serializer/index.md), which you may provide for types
you do not own, or free `to_json`/`from_json` functions in the namespace of the type. Place them where they are
visible before any code that converts the type; see
[Why isn't my `to_json` found?](arbitrary_types.md#why-isnt-my-to_json-or-from_json-found).

## Smart pointers

A `std::shared_ptr<T>` or `std::unique_ptr<T>` is written as the value it points to, or as `#!json null` for an empty
pointer, and read back by allocating a new `T`:

??? example "Example: serialize shared_ptr and unique_ptr"

    ```cpp
    #include <iostream>
    #include <memory>
    #include <vector>
    #include <nlohmann/json.hpp>
    
    using json = nlohmann::json;
    
    namespace nlohmann
    {
    template <typename T>
    struct adl_serializer<std::shared_ptr<T>>
    {
        static void to_json(json& j, const std::shared_ptr<T>& p)
        {
            if (p)
            {
                j = *p;
            }
            else
            {
                j = nullptr;
            }
        }
    
        static void from_json(const json& j, std::shared_ptr<T>& p)
        {
            if (j.is_null())
            {
                p = nullptr;
            }
            else
            {
                p = std::make_shared<T>(j.get<typename std::remove_const<T>::type>());
            }
        }
    };
    
    template <typename T>
    struct adl_serializer<std::unique_ptr<T>>
    {
        static void to_json(json& j, const std::unique_ptr<T>& p)
        {
            if (p)
            {
                j = *p;
            }
            else
            {
                j = nullptr;
            }
        }
    
        static void from_json(const json& j, std::unique_ptr<T>& p)
        {
            if (j.is_null())
            {
                p = nullptr;
            }
            else
            {
                p = std::make_unique<T>(j.get<T>());
            }
        }
    };
    } // namespace nlohmann
    
    struct point
    {
        int x;
        int y;
    };
    
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(point, x, y)
    
    int main()
    {
        // an empty pointer is written as null
        const std::vector<std::shared_ptr<point>> points = {std::make_shared<point>(point{1, 2}), nullptr};
        const json j = points;
        std::cout << j << '\n';
    
        // reading allocates new objects
        const auto back = j.get<std::vector<std::shared_ptr<point>>>();
        std::cout << back[0]->x << ", " << back[0]->y << ", " << (back[1] == nullptr) << '\n';
    
        // pointers to const and unique_ptr work as well
        const auto const_ptr = j[0].get<std::shared_ptr<const point>>();
        const auto unique = j[0].get<std::unique_ptr<point>>();
        std::cout << const_ptr->y << ", " << unique->x << '\n';
    }
    
    ```

    Output:

    ```
    [{"x":1,"y":2},null]
    1, 2, 1
    2, 1
    
    ```

With this, containers of smart pointers, pointers to `const`, and members of these types in your own structs convert as
usual. A pointer to a base class cannot be filled this way, because `T` would have
to be created as a derived type; see the next section.

Reading creates a new object. Two `shared_ptr`s that pointed to the same object are written twice and read back as two
separate objects.

## Class hierarchies

!!! tip "Derived classes whose type is known at compile time"

    If you only need to serialize the data members of a derived class, and the code always knows the concrete type, you do
    not need a type tag. The [`NLOHMANN_DEFINE_DERIVED_TYPE_*` macros](arbitrary_types.md#simplify-your-life-with-macros)
    (since version 3.12.0) add the members of the derived class to those of its base class. This section is for the case
    where the concrete type is only known at run time, such as a `std::unique_ptr<shape>` that holds a circle or a
    rectangle.

JSON has no notion of types, so a value in a hierarchy needs a **type tag** that says which derived class to create.
Write the tag in the object, and select the class from it when reading:

??? example "Example: serialize a class hierarchy with a type tag"

    ```cpp
    #include <iostream>
    #include <memory>
    #include <stdexcept>
    #include <vector>
    #include <nlohmann/json.hpp>
    
    using json = nlohmann::json;
    
    struct shape
    {
        virtual ~shape() = default;
        virtual json serialize() const = 0;
    };
    
    struct circle : shape
    {
        double radius;
    
        explicit circle(double r) : radius(r) {}
    
        json serialize() const override
        {
            return {{"type", "circle"}, {"radius", radius}};
        }
    };
    
    struct rectangle : shape
    {
        double width;
        double height;
    
        rectangle(double w, double h) : width(w), height(h) {}
    
        json serialize() const override
        {
            return {{"type", "rectangle"}, {"width", width}, {"height", height}};
        }
    };
    
    namespace nlohmann
    {
    template <>
    struct adl_serializer<std::unique_ptr<shape>>
    {
        static void to_json(json& j, const std::unique_ptr<shape>& p)
        {
            j = p ? p->serialize() : json(nullptr);
        }
    
        static void from_json(const json& j, std::unique_ptr<shape>& p)
        {
            if (j.is_null())
            {
                p.reset();
                return;
            }
    
            const auto& type = j.at("type").get_ref<const std::string&>();
            if (type == "circle")
            {
                p = std::make_unique<circle>(j.at("radius").get<double>());
            }
            else if (type == "rectangle")
            {
                p = std::make_unique<rectangle>(j.at("width").get<double>(), j.at("height").get<double>());
            }
            else
            {
                throw std::invalid_argument("unknown shape type: " + type);
            }
        }
    };
    } // namespace nlohmann
    
    int main()
    {
        std::vector<std::unique_ptr<shape>> shapes;
        shapes.push_back(std::make_unique<circle>(1.5));
        shapes.push_back(std::make_unique<rectangle>(2, 3));
    
        const json j = shapes;
        std::cout << j << '\n';
    
        // reading creates objects of the derived types
        const auto back = j.get<std::vector<std::unique_ptr<shape>>>();
        std::cout << std::boolalpha;
        std::cout << "first is a circle: " << (dynamic_cast<circle*>(back[0].get()) != nullptr) << '\n';
        std::cout << "second is a rectangle: " << (dynamic_cast<rectangle*>(back[1].get()) != nullptr) << '\n';
    
        // an unknown type tag is reported
        try
        {
            json{{"type", "star"}}.get<std::unique_ptr<shape>>();
        }
        catch (const std::invalid_argument& e)
        {
            std::cout << e.what() << '\n';
        }
    }
    
    ```

    Output:

    ```
    [{"radius":1.5,"type":"circle"},{"height":3.0,"type":"rectangle","width":2.0}]
    first is a circle: true
    second is a rectangle: true
    unknown shape type: star
    
    ```

A `#!cpp std::vector<std::unique_ptr<shape>>` converts to an array of tagged objects and back, creating a `circle`
and a `rectangle`. The same works for `std::shared_ptr<shape>`. Remember the virtual destructor: without it, deleting a
derived object through the base pointer is undefined behavior.

## `std::variant`

A variant has the same problem: the alternative must be recorded. If the alternatives are your own types, write a type
tag next to their members, exactly as for a hierarchy:

??? example "Example: serialize a std::variant with a type tag"

    ```cpp
    #include <iostream>
    #include <stdexcept>
    #include <variant>
    #include <vector>
    #include <nlohmann/json.hpp>
    
    using json = nlohmann::json;
    
    namespace geo
    {
    struct circ
    {
        double radius;
    };
    
    struct rect
    {
        double width;
        double height;
    };
    
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(circ, radius)
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(rect, width, height)
    
    using figure = std::variant<circ, rect>;
    
    void to_json(json& j, const figure& f)
    {
        std::visit([&j](const auto & alternative)
        {
            j = alternative;
        }, f);
        j["type"] = std::holds_alternative<circ>(f) ? "circ" : "rect";
    }
    
    void from_json(const json& j, figure& f)
    {
        const auto& type = j.at("type").get_ref<const std::string&>();
        if (type == "circ")
        {
            f = j.get<circ>();
        }
        else if (type == "rect")
        {
            f = j.get<rect>();
        }
        else
        {
            throw std::invalid_argument("unknown figure type: " + type);
        }
    }
    } // namespace geo
    
    int main()
    {
        const std::vector<geo::figure> figures = {geo::circ{2}, geo::rect{3, 4}};
    
        const json j = figures;
        std::cout << j << '\n';
    
        const auto back = j.get<std::vector<geo::figure>>();
        std::cout << "alternatives read back: " << back[0].index() << ", " << back[1].index() << '\n';
    }
    
    ```

    Output:

    ```
    [{"radius":2.0,"type":"circ"},{"height":4.0,"type":"rect","width":3.0}]
    alternatives read back: 0, 1
    
    ```

In the example, the functions are found
because `geo` is the namespace of the template arguments of `#!cpp std::variant<circ, rect>`; for a variant of only
standard types (for example `#!cpp std::variant<int, std::string>`) there is no such namespace, and you need an
`adl_serializer` specialization or a wrapper type of your own.

If the alternatives are JSON-native (numbers, strings, ...), a variant such as `#!cpp std::variant<int, std::string>`
can instead be written as the plain value, and read by testing the JSON type (`is_number_integer()`, `is_string()`)
to choose the alternative.

## `std::chrono`

A duration is written as an object with the keys `unit` and `value`, for example `{"unit": "ms", "value": 1500}`, so
the JSON value is self-describing. The serializer names the unit of the period (`ns`, `us`, `ms`, `s`, `min`, `h`;
extend the list for other periods), and the deserializer rejects a value whose unit differs from the requested
duration type instead of silently misreading it:

??? example "Example: serialize durations and system_clock time points"

    ```cpp
    #include <chrono>
    #include <iostream>
    #include <stdexcept>
    #include <string>
    #include <nlohmann/json.hpp>
    
    using json = nlohmann::json;
    
    // the name of a period; extend the list for the periods you use
    template <typename Period> const char* unit_name();
    template <> const char* unit_name<std::nano>()
    {
        return "ns";
    }
    template <> const char* unit_name<std::micro>()
    {
        return "us";
    }
    template <> const char* unit_name<std::milli>()
    {
        return "ms";
    }
    template <> const char* unit_name<std::ratio<1>>()
    {
        return "s";
    }
    template <> const char* unit_name<std::ratio<60>>()
    {
        return "min";
    }
    template <> const char* unit_name<std::ratio<3600>>()
    {
        return "h";
    }
    
    namespace nlohmann
    {
    template <typename Rep, typename Period>
    struct adl_serializer<std::chrono::duration<Rep, Period>>
    {
        static void to_json(json& j, const std::chrono::duration<Rep, Period>& d)
        {
            j = {{"unit", unit_name<Period>()}, {"value", d.count()}};
        }
    
        static void from_json(const json& j, std::chrono::duration<Rep, Period>& d)
        {
            if (j.at("unit").get<std::string>() != unit_name<Period>())
            {
                throw std::invalid_argument("unexpected unit " + j.at("unit").dump());
            }
            d = std::chrono::duration<Rep, Period>(j.at("value").get<Rep>());
        }
    };
    
    template <typename Duration>
    struct adl_serializer<std::chrono::time_point<std::chrono::system_clock, Duration>>
    {
        static void to_json(json& j, const std::chrono::time_point<std::chrono::system_clock, Duration>& t)
        {
            j = t.time_since_epoch();
        }
    
        static void from_json(const json& j, std::chrono::time_point<std::chrono::system_clock, Duration>& t)
        {
            t = std::chrono::time_point<std::chrono::system_clock, Duration>(j.get<Duration>());
        }
    };
    } // namespace nlohmann
    
    int main()
    {
        using namespace std::chrono;
    
        std::cout << std::boolalpha;
    
        // the unit is part of the JSON value
        const json timeout = milliseconds(1500);
        std::cout << "duration: " << timeout << '\n';
        std::cout << "as milliseconds: " << timeout.get<milliseconds>().count() << '\n';
    
        // reading with a different unit is rejected
        try
        {
            timeout.get<seconds>();
        }
        catch (const std::invalid_argument& e)
        {
            std::cout << "error: " << e.what() << '\n';
        }
    
        // a system_clock time point is the time since the Unix epoch
        const time_point<system_clock, milliseconds> t(milliseconds(1700000000123));
        const json stamp = t;
        std::cout << "time point: " << stamp << '\n';
    
        const auto back = stamp.get<time_point<system_clock, milliseconds>>();
        std::cout << "round trip: " << (back == t) << '\n';
    }
    
    ```

    Output:

    ```
    duration: {"unit":"ms","value":1500}
    as milliseconds: 1500
    error: unexpected unit "ms"
    time point: {"unit":"ms","value":1700000000123}
    round trip: true
    
    ```

A `system_clock::time_point` with millisecond precision is written as the duration since the Unix epoch, that is, as an object with `unit` and `value`.
The time point serializer is limited to `system_clock`,
because the epoch of other clocks (for example `steady_clock`) has no meaning outside the running program.

If you prefer a text representation such as ISO 8601 (`2023-11-14T22:13:20Z`), write the string with
`#!cpp std::format("{:%FT%TZ}", t)` and read it with `std::chrono::parse` (both C++20), or with a date library, in the
same two functions.

## See also

- [Arbitrary type conversions](arbitrary_types.md) - the conversion mechanism and macros
- [Why isn't my `to_json` found?](arbitrary_types.md#why-isnt-my-to_json-or-from_json-found) - troubleshoot conversion
  functions that are not picked up
- [Converting values](conversions.md) - `get`, implicit conversions, and `std::optional`
- [`NLOHMANN_DEFINE_DERIVED_TYPE`](../api/macros/nlohmann_define_derived_type.md) - conversion functions for derived classes
- [`adl_serializer`](../api/adl_serializer/index.md) - customize conversions for third-party types
- [`get`](../api/basic_json/get.md) - convert a JSON value to a C++ type

