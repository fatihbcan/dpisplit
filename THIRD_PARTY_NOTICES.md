# Third-party components

## WinDivert 2.2.2

Release zips ship `WinDivert.dll` and `WinDivert64.sys` unmodified, taken from
the official release
[`WinDivert-2.2.2-A.zip`](https://github.com/basil00/WinDivert/releases/tag/v2.2.2)
by basil00. They are not stored in this repository; the release workflow
downloads them and checks their SHA-256 before packaging.

WinDivert is dual-licensed under the **GNU Lesser General Public License v3**
and the **GNU General Public License v2**. dpisplit loads `WinDivert.dll`
dynamically at run time and does not modify it. Source code and full license
texts: https://github.com/basil00/WinDivert. A copy of the WinDivert license
is included in every release zip as `WinDivert-LICENSE.txt`.

| File | SHA-256 |
|---|---|
| `WinDivert-2.2.2-A.zip` | `63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15` |
| `x64/WinDivert.dll` | `c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2` |
| `x64/WinDivert64.sys` | `8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2` |
