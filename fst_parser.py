#!/usr/bin/env python3
#------------------------------------------------------------------------------
# Name:        Main program FST parser
# Purpose:
#
# Author:      Vitaliy_Ko
#
# Created:     31.07.2018
# Copyright:   (c) Vitaliy_Ko 2018
# Licence:     <your licence>
#------------------------------------------------------------------------------
"""
This is __doc__
"""
import sys, os, glob
from datetime import datetime
from parsers.file_parsers import toDateTime, FstParser
from parsers.dict_parsers import load_dictionary_csv, load_dictionary_json
from parsers.dict_parsers import search_for_message, search_for_direction, search_for_pcap_data
import parsers.pcap


if __name__ == "__main__":
    if len(sys.argv) > 1:
        source = sys.argv[1].strip()
    else:
        source = input('Please enter full path to processed file or directory:').strip()
        # source = r'c:\Users\vitaliy_ko\Documents\CEM\FST\GSMData\ZTE_FST_GSM_116_20180911080933_20180911081000_V6.50.310rP001_315_P49.dat'


    files = list()
    if os.path.exists(source):
        if os.path.isdir(source):
            files = glob.glob(os.path.join(source, 'ZTE_FST_*.dat'))
        else:
            files.append(source)
    else:
        print('Error: File or directory ' + source + ' does not exist!')
        exit()

    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    # Configuration parameters
    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    decodeRecordsContent = True
    saveMessageRawData = True
    decodeMessages = True
    saveToPcapFile = False   # If you set it True then decodeRecordsContent and saveMessageRawData also has to be True
    dirDecodedFiles = os.path.dirname(source)
    dirPcapFiles = os.path.join(os.path.dirname(source), 'pcap')
    # filterByImsi = ['000000000000000']
    filterByImsi = []
    tsn = 0  # May be used for uniq TSN generation in SCCP messages in pcap
    ssn = 0  # May be used for uniq SSN generation in SCCP messages in pcap
    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

    if not os.path.exists(dirDecodedFiles):
        print('Error: Directory for decoded files ' + dirDecodedFiles + ' does not exist!')
        exit()

    if not os.path.exists(dirPcapFiles):
        if dirPcapFiles == os.path.join(os.path.dirname(source),'pcap'):
            try:
                os.mkdir(dirPcapFiles)
            except:
                pass
        if not os.path.exists(dirPcapFiles):
            print('Error: Directory for pcap files ' + dirDecodedFiles + ' does not exist!')
            exit()

    # Load Dictionary
    cwd = os.getcwd()
    dict_messages = load_dictionary_csv(os.path.join(cwd, 'dicts', 'messages.csv'), ['protocolType','procedureType','messageType'])
    dict_directions_3g = load_dictionary_csv(os.path.join(cwd, 'dicts', 'directions_3g.csv'), ['id'])
    dict_directions_2g = load_dictionary_csv(os.path.join(cwd, 'dicts', 'directions_2g.csv'), ['id'])
    dict_protocols = load_dictionary_json(os.path.join(cwd, 'dicts', 'protocols.json'))
    dict_pcap = load_dictionary_json(os.path.join(cwd, 'dicts', 'protocols_pcap.json'))

    # Debugging !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    missed_messages = list()
    dict_messages_count = load_dictionary_csv(os.path.join(cwd, 'dicts', 'messages.csv'), ['protocolType','procedureType','messageType'])
    for msg in dict_messages_count:
        msg['count'] = 0
        msg['total_length'] = 0
    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

    for source_file in files:
        # Start file parsing
        source_file_name = os.path.basename(source_file)
        print('File: ' + source_file)
        print('\t{0} Start parsing...'.format(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        ssn +=1
        tsn = 0
        fstParser = FstParser()
        fileIinfo = fstParser.open(source_file)
        # Start writing decoded data to text file
        with open(os.path.join(dirDecodedFiles, source_file_name + '.decoded.txt'), 'w') as out_file:
            print('-'*80, file=out_file)
            print('FILE HEADER', file=out_file)
            print('\tElement ID: ' + str(fileIinfo['ElementId']), file=out_file)
            print('\tElement Mode: ' + str(fileIinfo['ElementMode']), file=out_file)
            print('\tFile type: ' + str(fileIinfo['FileType']), file=out_file)
            print('\tElement version: '+ fileIinfo['ElementVersion'], file=out_file)
            print('\tFile start timestamp: ' + str(fileIinfo['FileStartTimestamp']), file=out_file)
            print('\tFile end timestamp: ' + str(fileIinfo['FileEndTimestamp']), file=out_file)
            print('\tFile record number: ' + str(fileIinfo['FileRecordNumber']), file=out_file)
            print('\tFile No: ' + str(fileIinfo['FileNo']), file=out_file)

            if fileIinfo['FileRecordNumber'] > 0:
                rec = 0
                # Read all records wich fulfill filterByImsi criterias one by one
                for record in fstParser.readRecords(decodeRecordsContent, saveMessageRawData, filterByImsi):
                    # pprint(record)
                    print('\nDATA RECORD ' + str(rec), file=out_file)
                    print('\tRecord length: ' + str(record['recordLength']), file=out_file)
                    print('\t\tRecord Header: ', file=out_file)
                    print('\t\t\tUE ID Info: ', file=out_file)
                    print('\t\t\t\tGlobal Call ID: ' + str(record['recordHeader']['ueIdInfo']['GlobalCallId']), file=out_file)
                    print('\t\t\t\tIMSI Information: ', file=out_file)
                    print('\t\t\t\t\tIMSI Length: ' + str(record['recordHeader']['ueIdInfo']['ImsiLength']), file=out_file)
                    print('\t\t\t\t\tAccess Cell ID: ' + str(record['recordHeader']['ueIdInfo']['AccessCellId']), file=out_file)
                    print('\t\t\t\t\tIMSI Element: ' + str(record['recordHeader']['ueIdInfo']['ImsiElement']), file=out_file)
                    print('\t\t\tSource ID: ' + str(record['recordHeader']['SourceId']), file=out_file)
                    print('\t\t\tRecord type: ' + str(record['recordHeader']['RecordType']), file=out_file)
                    print('\t\t\tRecord TLV data length: ' + str(record['recordHeader']['RecordTlvDataLength']), file=out_file)
                    if record['recordHeader']['RecordTlvDataLength'] > 0:
                        print('\t\t\tRecord TLV data: ' + record['recordTlvData'], file=out_file)
                    print('\t\t\tMessage count: ' + str(record['recordHeader']['MessageCount']), file=out_file)
                    print('\t\t\tRecord content length: ' + str(record['recordHeader']['RecordContentLength']), file=out_file)
                    print('\t\t\tRecord sequence: ' + str(record['recordHeader']['RecordSequence']), file=out_file)

                    if decodeRecordsContent:
                        for message in record['recordContent']:
                            msg = search_for_message(dict_messages, dict_protocols, message['header']['protocolType'],
                                                    message['header']['procedureType'], message['header']['messageType'])

                            # Debugging !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                            if msg['messageName'] == '':
                                new_msg = True
                                for missed_msg in missed_messages:
                                    if (missed_msg['protocolType'] == message['header']['protocolType'] and
                                            missed_msg['procedureType'] == message['header']['procedureType'] and
                                            missed_msg['messageType'] == message['header']['messageType']):
                                        new_msg = False
                                        missed_msg['count'] += 1
                                        break
                                if new_msg:
                                    missed_messages.append({'protocolType': message['header']['protocolType'],
                                                            'procedureType': message['header']['procedureType'],
                                                            'messageType': message['header']['messageType'],
                                                            'count': 1})
                            else:
                                for msg_ in dict_messages_count:
                                    if (msg_['protocolType'] == message['header']['protocolType'] and
                                            msg_['procedureType'] == message['header']['procedureType'] and
                                            msg_['messageType'] == message['header']['messageType']):
                                        msg_['count'] += 1
                                        msg_['total_length'] += message['header']['rawDataLength']
                                        break
                            # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

                            print('\t\t\t\tMessage: ', file=out_file)
                            print('\t\t\t\t\tMessage header: ', file=out_file)
                            print('\t\t\t\t\t\tProtocol type: ' + str(message['header']['protocolType']) + ' ' + msg['protocolName'], file=out_file)
                            print('\t\t\t\t\t\tProcedure type: ' + str(message['header']['procedureType'])  + ' ' + msg['procedureName'], file=out_file)
                            print('\t\t\t\t\t\tMessage type: ' + str(message['header']['messageType'])   + ' ' + msg['messageName'], file=out_file)
                            if fileIinfo['ElementMode'] == 3:   # 3 - GSM
                                print('\t\t\t\t\t\tDirection: ' + str(message['header']['direction']) + ' ' + search_for_direction(dict_directions_2g, message['header']['direction']), file=out_file)
                            elif fileIinfo['ElementMode'] == 1: # 1 - UMTS
                                print('\t\t\t\t\t\tDirection: ' + str(message['header']['direction']) + ' ' + search_for_direction(dict_directions_3g, message['header']['direction']), file=out_file)
                            print('\t\t\t\t\t\tSecond: ' + str(toDateTime(seconds=message['header']['second'], milliseconds=message['header']['quatMillisecond']*4)), file=out_file)  #01.01.2000
                            print('\t\t\t\t\t\tService Cell ID: ' + str(message['header']['serviceCellId']), file=out_file)
                            print('\t\t\t\t\t\tMessage TLV data length: ' + str(message['header']['messageTlvDataLength']), file=out_file)
                            if message['header']['messageTlvDataLength'] > 0:
                                print('\t\t\t\t\t\tMessage TLV data: ' + message['tlvData'], file=out_file)
                            print('\t\t\t\t\t\tMessage sequence: ' + str(message['header']['messageSequence']), file=out_file)
                            print('\t\t\t\t\t\tRaw data length: ' + str(message['header']['rawDataLength']), file=out_file)
                            if saveMessageRawData:
                                print('\t\t\t\t\t\tRaw data: ' + message['rawData'], file=out_file)
                    else:
                        print('\t\t\tRecord Raw data: ' + record['recordRawContent'], file=out_file)
                    print('-'*80, file=out_file)

                    # Save to PCAP-file
                    if saveToPcapFile and decodeRecordsContent and saveMessageRawData:
                        tsn += 500
                        p = parsers.pcap.Pcap()
                        p.open(os.path.join(dirPcapFiles, '{0}_{1:06}_{2}.pcap'.format(str(record['recordHeader']['ueIdInfo']['ImsiElement']), rec, source_file_name)), tsn, ssn)
                        for message in record['recordContent']:
                            # Find proper Wireshark desector for message
                            if message['header']['protocolType'] == 100:
                                pass
                            elif (message['header']['protocolType'] == 101 or message['header']['protocolType'] == 102
                                    or message['header']['protocolType'] == 103 or message['header']['protocolType'] == 104
                                    or message['header']['protocolType'] == 151 or message['header']['protocolType'] == 152
                                    or message['header']['protocolType'] == 153):
                                pcap_data = search_for_pcap_data(dict_pcap, message['header']['protocolType'], message['header']['direction'],
                                        message['header']['procedureType'])
                            else:
                                pcap_data = None

                            # Write message to pcap file
                            if message['header']['protocolType'] != 100:
                                if pcap_data != None and pcap_data['pcap_data'] != None:
                                    p.write_message(msg_hex=message['rawData'],
                                            time=toDateTime(seconds=message['header']['second'], milliseconds=message['header']['quatMillisecond']*4),
                                            protocol=pcap_data['protocol'],
                                            pcap_data=pcap_data['pcap_data'])
                                else:
                                    raise Exception('Pcap saving exception: Protocol type:{0}, Procedure type:{1}, Message:{2}, Direction:{3}'.format(
                                        message['header']['protocolType'], message['header']['procedureType'],
                                        msg['procedureName'], message['header']['direction'])
                                    )
                        p.close()
                    rec += 1
        print('\t{0} Done'.format(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

    # Debugging !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    if len(missed_messages) > 0:
        print('\nThere are missed messages in file(s):')
        print(missed_messages)
    print('\nprotocolType,procedureType,messageType,messageName,count,total_length')
    for msg in dict_messages_count:
        print('{0},{1},{2},{3},{4},{5}'.format(msg['protocolType'], msg['procedureType'], msg['messageType'], msg['messageName'], msg['count'], msg['total_length']))
    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# END


