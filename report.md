# crypto

该项目实现了如下的功能：

1. 分组密码的加解密：DES AES128 SM4 的 CBC 模式
2. 流密码的加解密：RC4
3. LFSR 逆向算法：B-M
4. Hash 函数：SHA-224 SHA-256 SHA-384 SHA-512 SM3 SHA3-224 SHA3-384 SHA3-512

性能指标（Release 模式）：

```
Intel i7-7820HQ @ 2.90GHz
Algo DES Encrypt Throughput: 272.25 Mbps or 34.03 MiB/s
Algo DES Decrypt Throughput: 267.05 Mbps or 33.38 MiB/s
Algo AES128 Encrypt Throughput: 458.75 Mbps or 57.34 MiB/s
Algo AES128 Decrypt Throughput: 345.51 Mbps or 43.19 MiB/s
Algo SM4 Encrypt Throughput: 784.35 Mbps or 98.04 MiB/s
Algo SM4 Decrypt Throughput: 713.44 Mbps or 89.18 MiB/s
Algo RC4 Encrypt Throughput: 1361.06 Mbps or 170.13 MiB/s
Algo RC4 Decrypt Throughput: 1483.29 Mbps or 185.41 MiB/s
Algo SHA224 Throughput: 1028.57 Mbps or 128.57 MiB/s
Algo SHA256 Throughput: 881.47 Mbps or 110.18 MiB/s
Algo SHA384 Throughput: 1262.52 Mbps or 157.82 MiB/s
Algo SHA512 Throughput: 1205.54 Mbps or 150.69 MiB/s
Algo SM3 Throughput: 857.34 Mbps or 107.17 MiB/s
Algo SHA3-224 Throughput: 1120.88 Mbps or 140.11 MiB/s
Algo SHA3-256 Throughput: 1197.04 Mbps or 149.63 MiB/s
Algo SHA3-384 Throughput: 915.72 Mbps or 114.47 MiB/s
Algo SHA3-512 Throughput: 776.51 Mbps or 97.06 MiB/s

Intel Xeon E5-2670 v3 @ 2.30GHz
Algo DES Encrypt Throughput: 116.18 Mbps or 14.52 MiB/s
Algo DES Decrypt Throughput: 125.79 Mbps or 15.72 MiB/s
Algo AES128 Encrypt Throughput: 107.04 Mbps or 13.38 MiB/s
Algo AES128 Decrypt Throughput: 53.40 Mbps or 6.68 MiB/s
Algo SM4 Encrypt Throughput: 423.94 Mbps or 52.99 MiB/s
Algo SM4 Decrypt Throughput: 410.89 Mbps or 51.36 MiB/s
Algo RC4 Encrypt Throughput: 1085.30 Mbps or 135.66 MiB/s
Algo RC4 Decrypt Throughput: 1079.82 Mbps or 134.98 MiB/s
Algo SHA224 Throughput: 517.28 Mbps or 64.66 MiB/s
Algo SHA256 Throughput: 517.64 Mbps or 64.71 MiB/s
Algo SHA384 Throughput: 802.15 Mbps or 100.27 MiB/s
Algo SHA512 Throughput: 737.13 Mbps or 92.14 MiB/s
Algo SM3 Throughput: 451.45 Mbps or 56.43 MiB/s
Algo SHA3-224 Throughput: 170.15 Mbps or 21.27 MiB/s
Algo SHA3-256 Throughput: 247.10 Mbps or 30.89 MiB/s
Algo SHA3-384 Throughput: 228.56 Mbps or 28.57 MiB/s
Algo SHA3-512 Throughput: 143.91 Mbps or 17.99 MiB/s

AMD EPYC 7551 32-Core Processor
Algo DES Encrypt Throughput: 199.30 Mbps or 24.91 MiB/s
Algo DES Decrypt Throughput: 199.89 Mbps or 24.99 MiB/s
Algo AES128 Encrypt Throughput: 389.60 Mbps or 48.70 MiB/s
Algo AES128 Decrypt Throughput: 135.57 Mbps or 16.95 MiB/s
Algo SM4 Encrypt Throughput: 668.56 Mbps or 83.57 MiB/s
Algo SM4 Decrypt Throughput: 690.27 Mbps or 86.28 MiB/s
Algo RC4 Encrypt Throughput: 1537.89 Mbps or 192.24 MiB/s
Algo RC4 Decrypt Throughput: 1538.65 Mbps or 192.33 MiB/s
Algo SHA224 Throughput: 1268.26 Mbps or 158.53 MiB/s
Algo SHA256 Throughput: 1271.67 Mbps or 158.96 MiB/s
Algo SHA384 Throughput: 1812.22 Mbps or 226.53 MiB/s
Algo SHA512 Throughput: 1810.33 Mbps or 226.29 MiB/s
Algo SM3 Throughput: 1271.67 Mbps or 158.96 MiB/s
Algo SHA3-224 Throughput: 614.55 Mbps or 76.82 MiB/s
Algo SHA3-256 Throughput: 597.95 Mbps or 74.74 MiB/s
Algo SHA3-384 Throughput: 501.03 Mbps or 62.63 MiB/s
Algo SHA3-512 Throughput: 344.76 Mbps or 43.10 MiB/s
```

## 编译方式

代码采用 CMake 作为构建工具，用如下命令进行编译：

```shell
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make # this might take some time
```

会产生三个可执行文件：

1. crypto：一个 cli，可以在命令行中进行各种运算，用 `./crypto -h` 获取帮助
2. crypto-bench：对实现的密码学算法进行测速，输入大小为 2KB
3. crypto-test：运行单元测试

## 代码组织

源代码都在当前目录下：

1. 实现块加密算法：aes128.cpp des.cpp sm4.cpp
2. 实现流加密算法：rc4.cpp
3. 实现 B-M 算法：bm.cpp
4. 实现 Hash 算法：sha2.cpp sha3.cpp sm3.cpp
5. crypto 工具：main.cpp
6. 单元测试：test.cpp catch.hpp
7. benchmark：bench.cpp
8. fuzz 测试：fuzz.sh

其中 catch.hpp 取自来自开源的 [Catch2 测试框架](https://github.com/catchorg/Catch2)，其开源 LICENSE 为 BSL-1.0。

## 算法优化

在实现算法的过程中，发现一些算法按照标准的伪代码执行，其速度较慢，可能不能达到要求，于是进行了一系列的优化。以 DES 为例，做了如下的优化：

1. 初始实现的情况下，它的吞吐率是 50Mbps
2. 按照 S 盒子输入的行和列进行预处理，吞吐率提高到了 60Mbps
3. 通过性能分析工具，发现最慢的点在 Expansion 这一步，有一个大的循环和很多的访存，于是按照置换表的规律，用位运算重新实现，吞吐率提高到了 80Mbps
4. 在第二步的基础上，由于 S 盒子和其后的 P 过程是可以合并的，可以进行预处理，吞吐率提高到了 240Mbps
5. 类似第三步，把 IP 置换表也用位运算重新实现，吞吐率提高到了 260Mbps

此外还尝试一些细微的优化，但因为没有显著的效果，所以没有使用。

作为对比， OpenSSL 在同样环境下运行的速度：

```
LibreSSL 2.8.3
built on: date not available
options:bn(64,64) rc4(16x,int) des(idx,cisc,16,int) aes(partial) blowfish(idx) 
compiler: information not available
The 'numbers' are in 1000s of bytes per second processed.
type             16 bytes     64 bytes    256 bytes   1024 bytes   8192 bytes
des cbc          79795.54k    81349.26k    81842.76k    81901.71k    82397.73k
```

相当于 650Mbps 的吞吐率，只能说 OpenSSL 太快了。其他算法也有一个类似的比例，OpenSSL 的实现大概是我的实现的两到三倍。

## 正确性测试

为了保证算法的正确性，在 test.cpp 中编写了许多单元测试，用来验证各个密码学算法的正确性。部分测试数据来自对应算法的标准，部分则是手动指定明文，用其他工具计算出密文后比对。编译后，运行 `./crypto-test` 即可进行测试。

另外，还编写了 fuzz.sh ，它会生成随机数据，然后调用 OpenSSL 和 crypto 进行计算，比如 OpenSSL 加密，crypto 解密然后比对结果和初始数据，也有反过来，crypto 加密，OpenSSL 解密然后比对。

对于 B-M 算法，按照课件中的例子进行了比对，每一步的结果是吻合的。

## 性能测试

性能测试程序为 `./crypto-bench` ，它会随机出 2KB 的明文、IV和密钥，并且把已经实现的密码学算法运行一遍，通过运行时间推算出吞吐率。对于加密算法，还会分别测量加密和解密。

因为 AES 算法的加解密并不是对称的，所以会有一个比较明显的速度的差别。其他加密算法加解密都差不多。SM4 的算法实现起来比较简单，吞吐率也比较高。

Hash 算法的性能大都比块加密算法快，其中 SHA2 算法随着位数增多而变快，因为块的大小增加了；SHA3 算法随着位数增多而变慢，因为块的大小减小了。SM3 与 SHA256 性能相当。
