JSON Patch Tests
================

These are test cases for implementations of [IETF JSON Patch (RFC6902)](http://tools.ietf.org/html/rfc6902).

Some implementations can be found at [jsonpatch.com](http://jsonpatch.com).


Test Format
-----------

Each test file is a JSON document that contains an array of test records. A
test record is an object with the following members:

- doc: The JSON document to test against
- patch: The patch(es) to apply
- expected: The expected resulting document, OR
- error: A string describing an expected error
- comment: A string describing the test
- disabled: True if the test should be skipped

All fields except 'doc' and 'patch' are optional. Test records consisting only
of a comment are also OK.


Files
-----

- tests.json: the main test file
- spec_tests.json: tests from the RFC6902 spec


Writing Tests
-------------

All tests should have a descriptive comment.  Tests should be as
simple as possible - just what's required to test a specific piece of
behavior.  If you want to test interacting behaviors, create tests for
each behavior as well as the interaction.

If an 'error' member is specified, the error text should describe the
error the implementation should raise - *not* what's being tested.
Implementation error strings will vary, but the suggested error should
be easily matched to the implementation error string.  Try to avoid
creating error tests that might pass because an incorrect error was
reported.

Please feel free to contribute!


Credits
-------

The seed test set was adapted from Byron Ruth's
[jsonpatch-js](https://github.com/bruth/jsonpatch-js/blob/master/test.js) and
extended by [Mike McCabe](https://github.com/mikemccabe).


License
-------

   Copyright 2014 The Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

