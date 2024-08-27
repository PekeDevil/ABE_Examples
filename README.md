# Index

- [Index](#index)
- [What is this about?](#what-is-this-about)
- [Examples and Time Tests](#examples-and-time-tests)
  - [Charm](#charm)
  - [Rabe](#rabe)
  - [GoFE](#gofe)
  - [OpenABE](#openabe)
- [A note on installation:](#a-note-on-installation)
  - [Charm Installation](#charm-installation)
    - [Recommended Python Version](#recommended-python-version)
    - [About Dependencies](#about-dependencies)
    - [Virtual Environment](#virtual-environment)
  - [OpenABE Installation](#openabe-installation)
- [Credit where credit is due](#credit-where-credit-is-due)

---

# What is this about?

This repository provides implementation examples for various Attribute-Based Encryption Libraries. The libraries this repo provides code for are:

- [Charm:](https://github.com/JHUISI/charm) A python🐍 library. The most complete one.
- [Rabe:](https://github.com/Fraunhofer-AISEC/rabe) A Rust🦀 library. Always use v0.3.1 upwards, since earlier versions use AES instead of AES-GCM.
- [GoFE:](https://github.com/fentec-project/gofe) A Go library, the only one for Go when this repo was created. It has a sister library written in C, [Cifer](https://github.com/fentec-project/CiFEr).
- [OpenABE:](https://github.com/zeutro/openabe) A C++ library. The most efficient one.

The repository has been created with the code used for the article ["Too many options: A survey of ABE libraries for developers"](https://arxiv.org/abs/2209.12742).

Therefore, it offers code for the timing measurement of different schemes provided by the libraries Charm, Rabe, Gofe and OpenABE. In all cases, both the code used to perform the timing measurements and a simplified code that serves as a basic example are provided.

# Examples and Time Tests

## Charm

We provide implementation examples for the following schemes:

- BSW07: [Original Paper](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=4223236&casa_token=sh82htu2-PsAAAAA:O3yMQkIpQ0tznUxEknLy0M8iwYZNGuS0fYbgMYAr5gIY9kHrq6cmnLocQ6TZNqsSnSPUCLvWnEyH&tag=1) - [Docs](https://jhuisi.github.io/charm/charm/schemes/abenc/abenc_bsw07.html) - [Time Test](Charm/TimeTests/BSW07.py)
- FAME: [Original Paper](https://eprint.iacr.org/2017/807.pdf?ref=https://githubhelp.com) - [Docs](https://jhuisi.github.io/charm/charm/schemes/abenc/ac17.html) - [Time Test](Charm/TimeTests/FAME_C17.py)
- LSW10: [Original Paper](https://eprint.iacr.org/2008/309.pdf) - [Docs](https://jhuisi.github.io/charm/charm/schemes/abenc/abenc_lsw08.html) - [Time Test](Charm/TimeTests/LSW10.py)
- LW11: [Original Paper](https://eprint.iacr.org/2010/351) - [Docs](https://jhuisi.github.io/charm/charm/schemes/abenc/dabe_aw11.html) - [Time Test](Charm/TimeTests/LW11/)
- RW15: [Original Paper](https://eprint.iacr.org/2015/016) - [Docs](https://jhuisi.github.io/charm/charm/schemes/abenc/abenc_maabe_rw15.html) - [Time Test](Charm/TimeTests/RW15.py)
- YAHK14: [Original Paper](https://www.iacr.org/archive/pkc2014/83830226/83830226.pdf) - [Docs](https://jhuisi.github.io/charm/charm/schemes/abenc/abenc_unmcpabe_yahk14.html) - [Time Test](Charm/TimeTests/YAHK14.py)

In addition, a common way to use ABE encryption is in a hybrid form with a symmetric encryption. For this purpose, Charm provides an abstraction layer that allows the hybrid cipher to be called directly. [The example](Charm/Examples/HybridExample.py) shows how it can be used.

## Rabe

- BSW07: [Original Paper](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=4223236&casa_token=sh82htu2-PsAAAAA:O3yMQkIpQ0tznUxEknLy0M8iwYZNGuS0fYbgMYAr5gIY9kHrq6cmnLocQ6TZNqsSnSPUCLvWnEyH&tag=1) - [Docs](https://docs.rs/rabe/0.4.0/rabe/schemes/bsw/index.html) - [Time Test](Rabe/rabe_BSW07/benches/bench_BSW07.rs) - [Example](Rabe/rabe_BSW07/src/lib.rs)
- FAME (KP-ABE): [Original Paper](https://eprint.iacr.org/2017/807.pdf?ref=https://githubhelp.com) - [Docs](https://docs.rs/rabe/0.4.0/rabe/schemes/ac17/index.html) - [Time Test](Rabe/rabe_KPABEFAME/benches/bench_ac17kpabe.rs) - [Example](Rabe/rabe_KPABEFAME/src/lib.rs)
- LW11: [Original Paper](https://eprint.iacr.org/2010/351) [Docs](https://docs.rs/rabe/0.4.0/rabe/schemes/aw11/index.html) - [Time Test](Rabe/rabe_LW11/benches/bench_lw11.rs) - [Example](Rabe/rabe_LW11/src/lib.rs)
- YCT14: [Original Paper](https://www.sciencedirect.com/science/article/abs/pii/S0167739X14002039?via%3Dihub) - [Docs](https://docs.rs/rabe/0.4.0/rabe/schemes/yct14/index.html) - [Time Test](Rabe/rabe_YCT14/benches/bench_yct14.rs) - [Example](Rabe/rabe_YCT14/src/lib.rs)

## GoFE

- FAME (KP-ABE): [Original Paper](https://eprint.iacr.org/2017/807.pdf?ref=https://githubhelp.com) - [Docs](https://github.com/fentec-project/gofe?tab=readme-ov-file#use-the-scheme-(examples)) - [Time Test](GoFE/FAME/pkg_test.go) - [Example](GoFE/FAME/main.go)
- LW11: [Original Paper](https://eprint.iacr.org/2010/351) - [Docs](https://github.com/fentec-project/gofe?tab=readme-ov-file#use-the-scheme-(examples)) - [Time Test](GoFE/LW11_module/LW11_test.go) - [Example](GoFE/LW11_module/LW11.go)

## OpenABE

- W11: [Original Paper](https://www.iacr.org/archive/pkc2011/65710055/65710055.pdf) - [Docs](https://github.com/zeutro/openabe/tree/master/docs) - [Time Test](OpenABE/W11_TimeTest.cpp) - [Example](OpenABE/W11_Example.cpp)

# A note on installation:

These experiments were conducted on a Raspberry PI Zero and a Raspberry PI 4 between 2022 and 2023. Thus, it is recommended that all the information in this repository be used as a guideline and that things may have changed over time.

Due to the architectures of these boards, it was sometimes necessary to make certain modifications to perform the installations correctly.

The main limitation of the Raspberry Pi Zero was its ARMv6 architecture, which is incompatible with certain libraries. In the case of the Raspberry PI 4, it was necessary to manage its compatibility with ‘old’ versions of certain distros.

Some of the modifications, tricks, and shortcuts used to install the libraries this repository provides examples of are described below.

## Charm Installation

### Recommended Python Version

For best compatibility, it is recommended to use Python versions 3.8 to 3.10. Python 3.12 introduces changes to the longintrepr.h header file location, which may cause issues with the Charm library. For more details, refer to [ this issue discussion.](https://github.com/JHUISI/charm/issues/307#issuecomment-2094110757).

### About Dependencies

While setting up the environment, you may need to install the following dependencies:

- libssl-dev
- flex
- bison

When configuring the mathematical library, Charm offers the possibility to use both PBC and Relic. However, I was unable to perform a successful installation with Relic and ended up using PBC.

### Virtual Environment

Finally, after several problems with dependencies and installations, I ended up working with Python virtual environments.

It is quite possible that you don't need to do this and that some of my problems came from incompatibilities derived from some versions of dependencies installed on the Raspberries.

However, if you are still having problems, [this tutorial](https://lrusso96.github.io/blog/cryptography/2021/03/04/charm-setup.html) was the one I followed to successfully install Charm.

## OpenABE Installation

The original OpenABE library does not support compilation on ARM architectures. Therefore, [IBM](https://github.com/IBM/openabe/tree/master) modified the makefile used by OpenABE to compile relic. In this way, IBM was able to [make it ARM-compatible](https://github.com/IBM/openabe/blob/master/src/Makefile#L35).

The main modifications are related to the [parameters](https://github.com/IBM/openabe/blob/12ea3e4cc64f779e9e938652543e09dac62fb0db/src/Makefile#L35) with which relic is compiled. However, these modifications were insufficient to run OpenABE on ARMv6.

Therefore the makefile was modified again following the help of the [relic repository](https://github.com/relic-toolkit/relic/issues/211). The [final result](https://github.com/zeutro/openabe/blob/b8f9d3c8a2620c1185ca972248f7af39c1eae68c/deps/relic/Makefile) was used to compile OpenABE on both ARMv6 and ARMv8.

Finally another common problem in the OpenABE installation is that it uses the [GoogleTest](https://github.com/google/googletest), and the location of the files in this repository often varies. Therefore it may be necessary to modify the [download_gtest.sh](https://github.com/zeutro/openabe/blob/master/deps/gtest/download_gtest.sh) file and adjust the [GTEST_LINK](https://github.com/zeutro/openabe/blob/b8f9d3c8a2620c1185ca972248f7af39c1eae68c/deps/gtest/download_gtest.sh#L10C1-L10C11).

---

# Credit where credit is due

This repo only provides implemenation examples. They are not supposed to be infalible, just a starting point for developers, since when I had to work with them sometimes documentation was a bit dense. Well, that or it required more knowhow than the one I had. Therefore, altough this repo may be useful, the ones that actually made it possible are the original libraries developers.

If, despite everything, you still want to help me, you can check out the paper I wrote analysing these libraries to the best of my knowledge: [ArXiv](https://arxiv.org/abs/2209.12742)

    @article{mosteiro2022too,
        title={Too Many Options: A Survey of ABE Libraries for Developers},
        author={Mosteiro-Sanchez, Aintzane and Barcelo, Marc and Astorga, Jasone and Urbieta, Aitor},
        journal={arXiv preprint arXiv:2209.12742},
        url: {https://arxiv.org/abs/2209.12742},
        year={2022}
    }

---
