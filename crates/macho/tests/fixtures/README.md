# Darwin RTTI fixtures

These fixtures exercise real Apple Itanium ABI output, including coalesced
`type_info` records, Darwin's high-bit non-unique type-name tag, virtual and
multiple inheritance, covariant thunks, and pointer-to-member RTTI.

Rebuild them on macOS with the system Clang:

```sh
xcrun clang++ -std=c++20 -dynamiclib -arch arm64 \
  -mmacosx-version-min=11.0 -fvisibility=hidden \
  darwin-tagged-rtti.cpp -o arm64-darwin-tagged-rtti.dylib

xcrun clang++ -std=c++20 -dynamiclib -arch x86_64 \
  -mmacosx-version-min=11.0 -fvisibility=hidden \
  darwin-tagged-rtti.cpp -o x86_64-darwin-tagged-rtti.dylib
```

The checked-in binaries are test inputs, not release artifacts. Their SHA-256
digests are:

```text
1fa0f690fb0f88c28c5f5a1557ecab9276d4a2ec1a9b6cd783032fd11f86eb19  arm64-darwin-tagged-rtti.dylib
fa17edf2dc6325af750a9cef11c87ab07db32b10840d8bccb22fb111843cbdeb  x86_64-darwin-tagged-rtti.dylib
32acede30b57ae60ba0a824a91e7b48bd26a9a8d885f7006c2b7ba1416772dd3  darwin-tagged-rtti.cpp
```
