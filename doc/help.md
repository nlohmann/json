## error: 'to_string' is not a member of 'std'

This is an error that might come up when using certain GNU based compilers, including:

* MinGW 4.7, 4.8
* Android NDK
* ...

This is not an issue with this json tool, but rather with the compiler itself. Here's how I fixed it, thanks to [this page](http://tehsausage.com/mingw-to-string). I do not guarantee that this will work, only that it worked for me.

### mingw/include/wchar.h, mingw/include/stdio.h

(This same snippet needs replacing in two header files)

```
-/* These differ from the ISO C prototypes, which have a maxlen parameter like snprintf.  */
-#ifndef __STRICT_ANSI__
-_CRTIMP int __cdecl __MINGW_NOTHROW    swprintf (wchar_t*, const wchar_t*, ...);
-_CRTIMP int __cdecl __MINGW_NOTHROW    vswprintf (wchar_t*, const wchar_t*, __VALIST);
-#endif
+__CRT_INLINE int __cdecl __MINGW_NOTHROW swprintf (wchar_t* buffer, size_t count, const wchar_t* format, ...)
+{
+  __builtin_va_list argptr;
+  __builtin_va_start(argptr, format);
+  return _vsnwprintf(buffer, count, format, argptr);
+}
+
+__CRT_INLINE int __cdecl __MINGW_NOTHROW vswprintf (wchar_t* buffer, size_t count, const wchar_t* format, __VALIST argptr)
+{
+  return _vsnwprintf(buffer, count, format, argptr);
+}
```

### mingw\lib\gcc\mingw32\4.7.0\include\c++\mingw32\bits\os_defines.h

This preprocessor flag needs to be removed

```
-#define _GLIBCXX_HAVE_BROKEN_VSWPRINTF 1
```

### MinGW\lib\gcc\mingw32\4.8.1\include\c++\mingw32\bits\c++config.h

This may or may not be necessary, but if so, then makefiles will require `-std=gnu++11` too.

```
-/* #define _GLIBCXX_USE_C99 1 */
+#define _GLIBCXX_USE_C99 1
```