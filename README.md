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
  - [Rabe Installation](#rabe-installation)
  - [GoFE Installation](#gofe-installation)
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

- BSW07: [Original Paper](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=4223236&casa_token=sh82htu2-PsAAAAA:O3yMQkIpQ0tznUxEknLy0M8iwYZNGuS0fYbgMYAr5gIY9kHrq6cmnLocQ6TZNqsSnSPUCLvWnEyH&tag=1) - [Docs] - [Time Test] TO DO - [Example]
- FAME (KP-ABE): [Original Paper](https://eprint.iacr.org/2017/807.pdf?ref=https://githubhelp.com) - [Docs] - [Time Test] TO DO - [Example]
- LW11: [Original Paper](https://eprint.iacr.org/2010/351) [Docs] - [Time Test] TO DO - [Example]
- YCT14: [Original Paper](https://www.sciencedirect.com/science/article/abs/pii/S0167739X14002039?via%3Dihub) - [Docs] - [Time Test] TO DO - [Example]

## GoFE

- FAME (KP-ABE): [Original Paper](https://eprint.iacr.org/2017/807.pdf?ref=https://githubhelp.com) - [Docs] - [Time Test] TO DO - [Example]
- LW11: [Original Paper](https://eprint.iacr.org/2010/351) - [Docs] - [Time Test] TO DO - [Example]

## OpenABE

- W11: [Original Paper](https://www.iacr.org/archive/pkc2011/65710055/65710055.pdf) - [Docs] - [Time Test] TO DO - [Example]
- GPSW06: [Original Paper](https://eprint.iacr.org/2006/309.pdf?ref=https://githubhelp.com) - [Docs] [Time Test] TO DO - [Example]

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

## Rabe Installation
TO DO

## GoFE Installation
TO DO

## OpenABE Installation
TO DO

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
