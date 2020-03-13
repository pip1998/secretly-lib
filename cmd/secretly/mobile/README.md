# Mobile

Package mobile implements [gomobile](https://github.com/golang/mobile) bindings for ipfs. Current implementation servers as a drop-in replacement for `lib` package.

The framework name is generated from the package name, hence these things are done intentionally

# Usage

To manually build library, run following commands:

### iOS

```
gomobile bind -v -target=ios github.com/pip1998/secretly-lib/cmd/secretly/mobile
```
This will produce `mobile.framework` file in the current directory, which can be used in iOS project.

### Android

```
gomobile bind -v -target=android -javapkg com.zcytech.secretly.lib github.com/pip1998/secretly-lib/cmd/secretly/mobile
```
This will generate `mobile.aar` file in the current dir.

# Notes

See [https://github.com/golang/go/wiki/Mobile](https://github.com/golang/go/wiki/Mobile) for more information on `gomobile` usage.
