#!/usr/bin/env python
from boofuzz import *


def main():

    session = Session(
        target=Target(
            connection=SocketConnection("127.0.0.1", 4433, proto='tcp')))

    s_initialize("ClientHello")

    s_byte(22, fuzzable=False)

    s_byte(0x03, fuzzable=False)
    s_byte(0x01, fuzzable=False)
    s_size("header", length=2, endian=">", fuzzable=False)
    if s_block_start("header"):

        # ClientHello
        s_byte(1, fuzzable=False)

        s_size("clienthello", length=3, endian=">", fuzzable=False)
        if s_block_start("clienthello"):
            # Version
            s_byte(0x03, fuzzable=False)
            s_byte(0x03, fuzzable=False)

            # Random
            s_random("a" * 32, min_length=32, max_length=32)

            # Session ID length
            s_size("sessionid", length=1, endian=">", fuzzable=False)
            if s_block_start("sessionid"):
                # Session ID
                s_random("a" * 32, min_length=0, max_length=0xff)
            s_block_end("sessionid")

            # Cipher Suites
            s_size("ciphersuites", length=2, endian=">", fuzzable=False)
            if s_block_start("ciphersuites"):
                if s_block_start("ciphers"):
                    s_bit_field(0x1301, width=16, endian=">")
                    s_bit_field(0x1302, width=16, endian=">")
                    s_bit_field(0x1303, width=16, endian=">")
                    s_bit_field(0x1304, width=16, endian=">")

                    s_bit_field(0xc02c, width=16, endian=">")
                    s_bit_field(0xc030, width=16, endian=">")
                    s_bit_field(0xcca9, width=16, endian=">")
                    s_bit_field(0xcca8, width=16, endian=">")

                    s_bit_field(0xc0ad, width=16, endian=">")
                    s_bit_field(0xc02b, width=16, endian=">")
                    s_bit_field(0xc02f, width=16, endian=">")
                    s_bit_field(0xc0ac, width=16, endian=">")

                    s_bit_field(0xc023, width=16, endian=">")
                    s_bit_field(0xc027, width=16, endian=">")
                    s_bit_field(0xc00a, width=16, endian=">")
                    s_bit_field(0xc014, width=16, endian=">")

                    s_bit_field(0xc009, width=16, endian=">")
                    s_bit_field(0xc013, width=16, endian=">")
                    s_bit_field(0x009d, width=16, endian=">")
                    s_bit_field(0xc09d, width=16, endian=">")

                    s_bit_field(0x009c, width=16, endian=">")
                    s_bit_field(0xc09c, width=16, endian=">")
                    s_bit_field(0x003d, width=16, endian=">")
                    s_bit_field(0x003c, width=16, endian=">")

                    s_bit_field(0x0035, width=16, endian=">")
                    s_bit_field(0x002f, width=16, endian=">")
                    s_bit_field(0x009f, width=16, endian=">")
                    s_bit_field(0xccaa, width=16, endian=">")

                    s_bit_field(0xc09f, width=16, endian=">")
                    s_bit_field(0x009e, width=16, endian=">")
                    s_bit_field(0xc09e, width=16, endian=">")
                    s_bit_field(0x006b, width=16, endian=">")

                    s_bit_field(0x0067, width=16, endian=">")
                    s_bit_field(0x0039, width=16, endian=">")
                    s_bit_field(0x0033, width=16, endian=">")
                    s_bit_field(0x00ff, width=16, endian=">")
                s_block_end("ciphers")
                s_repeat("ciphers", max_reps=1)

            s_block_end("ciphersuites")

            # Cipher Suites
            s_size("compressionmethods", length=1, endian=">", fuzzable=False)
            if s_block_start("compressionmethods"):
                # null method
                s_byte(0)
            s_block_end("compressionmethods")

            # Cipher Suites
            s_size("extensions", length=2, endian=">", fuzzable=False)
            if s_block_start("extensions"):

                # Supported versions
                if s_block_start("ext_version_block"):
                    s_bit_field(0x002b, width=16, endian=">")
                    s_size("ext_versions", length=2, endian=">", fuzzable=False)
                    if s_block_start("ext_versions"):
                        s_size("ext_versions_list", length=1, endian=">", fuzzable=False)
                        if s_block_start("ext_versions_list"):
                            s_bit_field(0x0304, width=16, endian=">")
                            s_bit_field(0x0303, width=16, endian=">")
                            s_bit_field(0x0302, width=16, endian=">")
                            s_bit_field(0x0301, width=16, endian=">")
                        s_block_end("ext_versions_list")

                    s_block_end("ext_versions")
                s_block_end("ext_version_block")
                s_repeat("ext_version_block", max_reps=2)
                # End supported versions

                # ec_point_formats
                if s_block_start("ec_point_formats_block"):
                    s_bit_field(0x000b, width=16, endian=">")
                    s_size("ec_point_formats", length=2, endian=">", fuzzable=False)
                    if s_block_start("ec_point_formats"):
                        s_size("ec_point_formats_list", length=1, endian=">", fuzzable=False)
                        if s_block_start("ec_point_formats_list"):
                            s_byte(0)
                            s_byte(1)
                            s_byte(2)
                        s_block_end("ec_point_formats_list")

                    s_block_end("ec_point_formats")
                s_block_end("ec_point_formats_block")
                s_repeat("ec_point_formats_block", max_reps=2)
                # End ec_point_formats

                # Supported groups
                if s_block_start("supported_groups_block"):
                    s_bit_field(0x000a, width=16, endian=">")
                    s_size("supported_groups", length=2, endian=">", fuzzable=False)
                    if s_block_start("supported_groups"):
                        s_size("supported_groups_list", length=2, endian=">", fuzzable=False)
                        if s_block_start("supported_groups_list"):
                            s_bit_field(0x001d, width=16, endian=">")
                            s_bit_field(0x0017, width=16, endian=">")
                            s_bit_field(0x0019, width=16, endian=">")
                            s_bit_field(0x0018, width=16, endian=">")
                        s_block_end("supported_groups_list")

                    s_block_end("supported_groups")
                s_block_end("supported_groups_block")
                s_repeat("supported_groups_block", max_reps=2)
                # End supported groups

                # next_protocol_negotiation
                if s_block_start("next_protocol_negotiation_block"):
                    s_bit_field(0x3374, width=16, endian=">")
                    s_size("next_protocol_negotiation", length=2, endian=">", fuzzable=False)
                    if s_block_start("next_protocol_negotiation"):
                        pass
                    s_block_end("next_protocol_negotiation")
                s_block_end("next_protocol_negotiation_block")
                s_repeat("next_protocol_negotiation_block", max_reps=2)
                # End next_protocol_negotiation

                # application_layer_protocol_negotiation
                if s_block_start("application_layer_protocol_negotiation_block"):
                    s_bit_field(0x0010, width=16, endian=">")
                    s_size("application_layer_protocol_negotiation", length=2, endian=">", fuzzable=False)
                    if s_block_start("application_layer_protocol_negotiation"):
                        s_size("application_layer_protocol_negotiation_list", length=2, endian=">", fuzzable=False)
                        if s_block_start("application_layer_protocol_negotiation_list"):
                            s_size("h2_len", length=1, endian=">", fuzzable=False)
                            if s_block_start("h2_len"):
                                s_string("h2", max_len=255)
                            s_block_end("h1_len")
                            s_size("h1_len", length=1, endian=">", fuzzable=False)
                            if s_block_start("h1_len"):
                                s_string("http/1.1", max_len=255)
                            s_block_end("h1_len")
                        s_block_end("application_layer_protocol_negotiation_list")

                    s_block_end("application_layer_protocol_negotiation")
                s_block_end("application_layer_protocol_negotiation_block")
                s_repeat("application_layer_protocol_negotiation_block", max_reps=2)
                # End application_layer_protocol_negotiation

                # encrypt_then_mac
                if s_block_start("encrypt_then_mac_block"):
                    s_bit_field(0x0016, width=16, endian=">")
                    s_size("encrypt_then_mac", length=2, endian=">", fuzzable=False)
                    if s_block_start("encrypt_then_mac"):
                        pass
                    s_block_end("encrypt_then_mac")
                s_block_end("encrypt_then_mac_block")
                s_repeat("encrypt_then_mac_block", max_reps=2)
                # End encrypt_then_mac

                # extended_master_secret
                if s_block_start("extended_master_secret_block"):
                    s_bit_field(0x0017, width=16, endian=">")
                    s_size("extended_master_secret", length=2, endian=">", fuzzable=False)
                    if s_block_start("extended_master_secret"):
                        pass
                    s_block_end("extended_master_secret")
                s_block_end("extended_master_secret_block")
                s_repeat("extended_master_secret_block", max_reps=2)
                # End extended_master_secret

                # post_handshake_auth
                if s_block_start("post_handshake_auth_block"):
                    s_bit_field(0x0031, width=16, endian=">")
                    s_size("post_handshake_auth", length=2, endian=">", fuzzable=False)
                    if s_block_start("post_handshake_auth"):
                        pass
                    s_block_end("post_handshake_auth")
                s_block_end("post_handshake_auth_block")
                s_repeat("post_handshake_auth_block", max_reps=2)
                # End post_handshake_auth

                # signature_algorithms
                if s_block_start("signature_algorithms_block"):
                    s_bit_field(0x000d, width=16, endian=">")
                    s_size("signature_algorithms", length=2, endian=">", fuzzable=False)
                    if s_block_start("signature_algorithms"):
                        s_size("signature_algorithms_list", length=2, endian=">", fuzzable=False)
                        if s_block_start("signature_algorithms_list"):
                            if s_block_start("signature_algorithms_rep"):
                                s_bit_field(0x0403, width=16, endian=">")
                                s_bit_field(0x0503, width=16, endian=">")
                                s_bit_field(0x0603, width=16, endian=">")
                                s_bit_field(0x0807, width=16, endian=">")
                                s_bit_field(0x0808, width=16, endian=">")
                                s_bit_field(0x0809, width=16, endian=">")
                                s_bit_field(0x080a, width=16, endian=">")
                                s_bit_field(0x080b, width=16, endian=">")
                                s_bit_field(0x0804, width=16, endian=">")
                                s_bit_field(0x0805, width=16, endian=">")
                                s_bit_field(0x0806, width=16, endian=">")
                                s_bit_field(0x0401, width=16, endian=">")
                                s_bit_field(0x0501, width=16, endian=">")
                                s_bit_field(0x0601, width=16, endian=">")
                                s_bit_field(0x0303, width=16, endian=">")
                                s_bit_field(0x0203, width=16, endian=">")
                                s_bit_field(0x0301, width=16, endian=">")
                                s_bit_field(0x0201, width=16, endian=">")
                                s_bit_field(0x0302, width=16, endian=">")
                                s_bit_field(0x0202, width=16, endian=">")
                                s_bit_field(0x0402, width=16, endian=">")
                                s_bit_field(0x0502, width=16, endian=">")
                                s_bit_field(0x0602, width=16, endian=">")
                            s_block_end("signature_algorithms_rep")
                            s_repeat("signature_algorithms_rep", max_reps=1)
                        s_block_end("signature_algorithms_list")

                    s_block_end("signature_algorithms")
                s_block_end("signature_algorithms_block")
                s_repeat("signature_algorithms_block", max_reps=2)
                # End signature_algorithms

                # psk_key_exchange_modes
                if s_block_start("psk_key_exchange_modes_block"):
                    s_bit_field(0x002d, width=16, endian=">")
                    s_size("psk_key_exchange_modes", length=2, endian=">", fuzzable=False)
                    if s_block_start("psk_key_exchange_modes"):
                        s_size("psk_key_exchange_modes_list", length=1, endian=">", fuzzable=False)
                        if s_block_start("psk_key_exchange_modes_list"):
                            if s_block_start("psk_key_exchange_modes_rep"):
                                s_byte(1)
                            s_block_end("psk_key_exchange_modes_rep")
                            s_repeat("psk_key_exchange_modes_rep", max_reps=1)
                        s_block_end("psk_key_exchange_modes_list")

                    s_block_end("psk_key_exchange_modes")
                s_block_end("psk_key_exchange_modes_block")
                s_repeat("psk_key_exchange_modes_block", max_reps=2)
                # End psk_key_exchange_modes

                # key_share
                if s_block_start("key_share_block"):
                    s_bit_field(0x0033, width=16, endian=">")
                    s_size("key_share_outer", length=2, endian=">", fuzzable=False)
                    if s_block_start("key_share_outer"):
                        s_size("key_share", length=2, endian=">", fuzzable=False)
                        if s_block_start("key_share"):
                            # Group
                            s_bit_field(0x001d, width=16, endian=">")
                            s_size("key_exchange", length=2, endian=">", fuzzable=False)
                            if s_block_start("key_exchange"):
                                s_random("a" * 32, min_length=0, max_length=0xffff)
                            s_block_end("key_exchange")

                        s_block_end("key_share")
                    s_block_end("key_share_outer")
                s_block_end("key_share_block")
                s_repeat("key_share_block", max_reps=2)
                # End key_share

            s_block_end("extensions")

        s_block_end("clienthello")

    s_block_end("header")


    session.connect(s_get("ClientHello"))


    session.fuzz()


if __name__ == "__main__":
    main()