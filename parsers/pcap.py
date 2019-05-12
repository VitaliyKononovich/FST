#!/usr/bin/env python3

import sys
import binascii
import datetime


class Pcap:

    def __init__(self):
        self.__pcap_file = None

        #Global header for pcap 2.4
        self.__pcap_global_header =  ('D4 C3 B2 A1'
                                    '02 00'         #File format major revision (i.e. pcap <2>.4)
                                    '04 00'         #File format minor revision (i.e. pcap 2.<4>)
                                    '00 00 00 00'
                                    '00 00 00 00'
                                    'FF FF 00 00'
                                    '01 00 00 00')

        #pcap packet header that must preface every packet
        #pcap_packet_header =   ('SS SS SS SS'   #Time sec
        #                        'US US US US'   #Time usec
        #                        'XX XX XX XX'   #Frame Size (little endian)
        #                        'YY YY YY YY')  #Frame Size (little endian)
        self.__pcap_packet_header = '{sec}{usec}{fs1}{fs2}'

        #eth_header = ('00 00 00 00 00 00'     #Source Mac
        #              '00 00 00 00 00 00'     #Dest Mac
        #              '08 00')                #Protocol (0x0800 = IP)
        self.__eth_header = '0000000000000000000000000800'

        #ip_header = ('45'                    #IP version and header length (multiples of 4 bytes)
        #             '00'
        #             'XX XX'                 #Length - will be calculated and replaced later
        #             '00 00'
        #             '40 00 40'
        #             '84'                    #Protocol (0x84 = SCTP)
        #             'YY YY'                 #Checksum - will be calculated and replaced later
        #             '7F 00 00 01'           #Source IP (Default: 127.0.0.1)
        #             '7F 00 00 02')          #Dest IP (Default: 127.0.0.2)
        self.__ip_header = '4500XXXX0000400040{protocol}YYYY{sourceIP}{destIP}'

        #udp_header =   ('P1 P1'                 #Src Port - will be replaced later
        #                'P2 P2'                 #Dest Port - will be replaced later
        #                'YY YY'                 #Length - will be calculated and replaced later
        #                '00 00')
        self.__udp_header = '{src_port}{dst_port}{length}0000'

        #sctp_header =   ('0b 59 0b 59 0e b0 00 2c 30 38 68 af 00 03' #ZZ ZZ - Chunk length
        #   'ZZ ZZ TT TT TT TT 00 0b SS SS PP PP PP PP' )     #TT TT TT TT - Transmission sequence number
        #                                                     #SS SS - = Stream sequence number
        #                                                     #PP PP PP PP - Payload protocol identifier
        self.__sctp_header = ('0b590b590eb0002c303868af0003'
           '{len_chunk}{tsn}000b{ssn}{protocol}')

        #m3ua_header =   ('01 00'
        #   '01 01 MM MM MM MM 02 00 00 08 00 00 00 08 02 10' #MM MM MM MM - = MTP3 Message length (must be multiple of 4)
        #   'PL PL OP OP OP OP DP DP DP DP 03 02 00 0a 06 12' #OP OP OP OP - = MTP3 OPC
        #   '96 07 00 01 16' )                               #DP DP DP DP - = MTP3 DPC
        #                                                     #PL PL - SS7 Message length = 23 + Message Length
        self.__m3ua_header = ('0100'
           '0101{len_mtp3}02000008000000080210'
           '{len_ss7}{opc}{dpc}0302000a0612'
           '9607000116')

        self.__sctp_tsn = 0
        self.__sctp_ssn = 0

        self.__ip_to_hex('127.0.0.1')


    def write_message(self, msg_hex:str, time:datetime, protocol:str, pcap_data:dict):
        sec = int((time - datetime.datetime(1970,1,1)).total_seconds()) -10800 #GMT+3
        sec = self.__guint32(sec)
        usec = self.__guint32(time.microsecond)


        if protocol == 'UM':  #Add additional Byte of MAC HEADER for proper decoding by Wireshark
            if pcap_data['pocedureName'] == 'RLC-MAC-DOWN':
                msg_hex = '51' +  msg_hex
            elif pcap_data['pocedureName'] == 'RLC-MAC-UP':
                msg_hex = '50' +  msg_hex

        len_msg = self.__getByteLength(msg_hex)
        len_padding = 0

        # RANAP, A
        if protocol == 'RANAP' or protocol == 'A':
            ip_protocol = '84' #sctp
            len_ss7_msg = 23 +  len_msg
            len_padding = (len_ss7_msg)%4
            if len_padding != 0:
                len_padding = 4 - len_padding
            len_mtp3_msg = 16 + len_ss7_msg + len_padding
            len_chunk = 16 + len_mtp3_msg
            m3ua_header = self.__m3ua_header.format(len_mtp3=self.__guint32(len_mtp3_msg),
                                                len_ss7=self.__guint16(len_ss7_msg),
                                                opc=self.__guint32(pcap_data['opc']),
                                                dpc=self.__guint32(pcap_data['dpc']))
            sctp_header = self.__prepare_sctp_header(len_chunk, 3)
            sctp_header += m3ua_header
            len_sctp = 12 + len_chunk
            len_ip = 20 + len_sctp
        # NBAP
        elif protocol == 'NBAP':
            ip_protocol = '84' #sctp
            len_padding = (len_msg)%4
            if len_padding != 0:
                len_padding = 4 - len_padding
            #len_chunk = 16 + len_msg + len_padding
            len_chunk = 16 + len_msg
            sctp_header = self.__prepare_sctp_header(len_chunk, 25)
            len_chunk += len_padding
            len_sctp = 12 + len_chunk
            len_ip = 20 + len_sctp
        # UU RRC
        elif protocol == 'UU' or protocol == 'Abis' or protocol == 'UM' or protocol == 'RNSAP':
            ip_protocol = '11' #udp
            port = 999
            if protocol == 'RNSAP':
                port = 5005
            else:
                if   pcap_data['pocedureName'] == 'DL DCCH':
                    port = 5000
                elif pcap_data['pocedureName'] == 'DL CCCH':
                    port = 5001
                elif pcap_data['pocedureName'] == 'UL DCCH':
                    port = 5002
                elif pcap_data['pocedureName'] == 'UL CCCH':
                    port = 5003
                elif pcap_data['pocedureName'] == 'BCCH FACH':
                    port = 5004
                elif pcap_data['pocedureName'] == 'PCCH':
                    port = 5006
                elif pcap_data['pocedureName'] == 'Abis':
                    port = 5100
                elif pcap_data['pocedureName'] == 'RLC-MAC-UP':
                    port = 5102
                elif pcap_data['pocedureName'] == 'RLC-MAC-DOWN':
                    port = 5103
                elif pcap_data['pocedureName'] == 'LLC':
                    port = 5104
            len_udp = 8 + len_msg
            udp_header = self.__udp_header.format(src_port=self.__guint16(port),
                                        dst_port=self.__guint16(port),
                                        length=self.__guint16(len_udp))
            len_ip = 20 + len_udp

        ip = self.__ip_header.format(protocol=ip_protocol, sourceIP=self.__ip_to_hex(pcap_data['source_ip']),
                                    destIP=self.__ip_to_hex(pcap_data['dest_ip']))
        ip = ip.replace('XXXX',self.__guint16(len_ip))
        checksum = self.__ip_checksum(ip.replace('YYYY','0000'))
        ip = ip.replace('YYYY',self.__guint16(checksum))

        len_pcap = len_ip + 14
        reverse_hex_str = self.__reverse_guint32(self.__guint32(len_pcap))
        pcaph = self.__pcap_packet_header.format(sec=self.__reverse_guint32(sec),
                                                usec=self.__reverse_guint32(usec),
                                                fs1=reverse_hex_str,
                                                fs2=reverse_hex_str)

        if protocol == 'RANAP' or protocol == 'NBAP' or protocol == 'A':
            bytestring = (pcaph + self.__eth_header + ip + sctp_header + msg_hex)
            if len_padding != 0:
                bytestring += '00'* len_padding
        elif protocol == 'UU' or protocol == 'Abis' or protocol == 'UM' or protocol == 'RNSAP':
            bytestring = (pcaph + self.__eth_header + ip + udp_header + msg_hex)
        else:
            raise Exception('Help!')

        self.__write(bytestring)

        self.__sctp_tsn += 1


    def open(self, filename:str, tsn=1, ssn=1):
        self.__pcap_file = open(filename, 'wb')
        self.__write(self.__pcap_global_header)
        self.__sctp_tsn = tsn
        self.__sctp_ssn = ssn


    def close(self):
        self.__pcap_file.close()


    def __write(self, bytestring:str):
        bytelist = bytestring.split()
        bytes = binascii.a2b_hex(''.join(bytelist))
        self.__pcap_file.write(bytes)


    def __getByteLength(self, s:str) -> int:
        return int(len(''.join(s.split())) / 2)


    def __reverse_guint32(self, str_hex:str) -> str:
        return str_hex[6:] + str_hex[4:6] + str_hex[2:4] + str_hex[:2]


    def __guint32(self, i:int) -> str:
        return '{0:08x}'.format(i)


    def __guint16(self, i:int) -> str:
        return '{0:04x}'.format(i)


    def __ip_to_hex(self, ip:str) -> str:
        octets = ip.split('.')
        return '{0:02x}{1:02x}{2:02x}{3:02x}'.format(int(octets[0]), int(octets[1]), int(octets[2]), int(octets[3]))


    #Splits the string into a list of tokens every n characters
    def __splitN(self, str1:str, n:int):
        return [str1[start:start+n] for start in range(0, len(str1), n)]


    #Calculates and returns the IP checksum based on the given IP Header
    def __ip_checksum(self, iph:str):
        #split into bytes
        words =self.__splitN(''.join(iph.split()),4)
        csum = 0;
        for word in words:
            csum += int(word, base=16)
        csum += (csum >> 16)
        csum = csum & 0xFFFF ^ 0xFFFF

        return csum

    def __prepare_sctp_header(self, len_chunk:int, protocol:int):
        return self.__sctp_header.format(len_chunk=self.__guint16(len_chunk),
                                                tsn=self.__guint32(self.__sctp_tsn),
                                                ssn=self.__guint16(self.__sctp_ssn),
                                                protocol=self.__guint32(protocol))


  # https://www.codeproject.com/Tips/612847/Generate-a-quick-and-easy-custom-pcap-file-using-P


#p = Pcap()
#p.open('test.pcap')
#p.write_message('20010012000001001f400b000001001e400440a00000', datetime.datetime.now(), 'RANAP', {'source_ip': '127.0.0.1', 'dest_ip': '127.0.0.2', 'opc': 100, 'dpc': 200})
#p.write_message('001846017319000003008f00020000002c0002006100d580060000ce800100', datetime.datetime.now(), 'NBAP', {'source_ip': '127.0.0.1', 'dest_ip': '127.0.0.2'})
#p.write_message('393844bbbb2570080354016d5b55da20', datetime.datetime.now(), 'UU', {'source_ip': '127.0.0.1', 'dest_ip': '127.0.0.2', 'pocedureName': 'UL CCCH'})
#p.close()



# https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html
# https://www.wireshark.org/docs/wsdg_html_chunked/wslua_dissector_example.html
# https://wiki.wireshark.org/Lua/Dissectors
# https://www.lua.org/manual/5.2/
# https://osqa-ask.wireshark.org/questions/39027/use-wireshark-as-a-decoder

# http://www.3gpp-message-analyser.com/decoder/grmc.htm
# https://www.wireshark.org/docs/dfref/
# https://wiki.wireshark.org/SampleCaptures#GSM
# https://www.corelatus.com/blog/Decoding_signalling_on_the_Abis_interface_with_Wireshark.html

"""
c:/Users/vitaliy_ko/Downloads/wireshark-2.6.3/epan/dissectors/  find register_dissector(

rrc.dl.dcch, rrc.ul.dcch, rrc.dl.ccch, rrc.ul.ccch, rrc.pcch, rrc.dl.shcch,
rrc.ul.shcch, rrc.bcch.fach, rrc.bcch.bch, rrc.mcch, rrc.msch, rrc.sysinfo,
rrc.sysinfo.cont, rrc.si.mib, rrc.si.sib1, rrc.si.sib2, rrc.si.sib3,
rrc.si.sib4, rrc.si.sib5, rrc.si.sib5bis, rrc.si.sib6, rrc.si.sib7,
rrc.si.sib8, rrc.si.sib9, rrc.si.sib10, rrc.si.sib11, rrc.si.sib11bis,
rrc.si.sib12, rrc.si.sib13, rrc.si.sib13-1, rrc.si.sib13-2, rrc.si.sib13-3,
rrc.si.sib13-4, rrc.si.sib14, rrc.si.sib15, rrc.si.sib15bis, rrc.si.sib15-1,
rrc.si.sib15-1bis, rrc.si.sib15-2, rrc.si.sib15-2bis, rrc.si.sib15-2ter,
rrc.si.sib15-3, rrc.si.sib15-3bis, rrc.si.sib15-4, rrc.si.sib15-5,
rrc.si.sib15-6, rrc.si.sib15-7, rrc.si.sib15-8, rrc.si.sib16, rrc.si.sib17,
rrc.si.sib18, rrc.si.sib19, rrc.si.sib20, rrc.si.sib21, rrc.si.sib22,
rrc.si.sb1, rrc.si.sb2, rrc.irat.ho_to_utran_cmd, rrc.irat.irat_ho_info,
rrc.ue_radio_access_cap_info
"""
