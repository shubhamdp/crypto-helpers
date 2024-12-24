#!/usr/bin/env python3
# Copyright 2022-24 Espressif Systems (Shanghai) PTE LTD
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from cryptography import x509

# CHIP OID for vendor id
VENDOR_ID = x509.ObjectIdentifier('1.3.6.1.4.1.37244.2.1')

# CHIP OID for product id
PRODUCT_ID = x509.ObjectIdentifier('1.3.6.1.4.1.37244.2.2')
