#!/usr/bin/env python3
"""
This module contains the class and functions for parsing ZTE FST GSM/UMTS files
"""
import struct
from datetime import datetime
from datetime import timedelta

def parser_umts_gsm(file: str, decodeRecordsContent = True, saveMessageRawData = True, filterByImsi = list()) -> dict:
    """
    Parsing ZTE FST GSM/UMTS file

    Open and parsing ZTE FST GSM/UMTS file according to the provided documentation:
    1. ZTE GSM Full Signaling Trace File Interface Specification V1.1
    2. ZTE UMTS Full Signaling Trace File Interface Introduction V1.0

    Parameters
    ----------
    file: str
        Full path to the (uncompressed) FST data file

    decodeRecordsContent = True
        Indicate if it is needed to decode Record content or just save Record Raw data

    saveMessageRawData = True
        Indicate if it is needed to save Message Raw data

    filterByImsi = list()
        Indicate if it is needed to filter Data Records by IMSIs. If list is empty,
        it means that no filter applied

    Returns
    -------
    dict
        Contains parsing results and consist of:
            'file': dict with internal information about the file like:
                    {'ElementId', 'ElementMode', 'FileType', 'ElementVersion',
                    'FileStartTimestamp', 'FileEndTimestamp', 'FileRecordNumber',
                    'FileNo'}

            'dataRecords': dict, contains data records from the file like:
                    {'recordLength', 'recordHeader':{ 'ueIdInfo': { 'GlobalCallId',
                            'ImsiLength', 'AccessCellId', 'ImsiElement'
                            },
                        'SourceId', 'RecordType', 'RecordTlvDataLength', 'MessageCount',
                        'RecordContentLength', 'RecordSequence'
                        },
                    'recordTlvData', 'recordContent', 'recordRawContent'}
                    Where 'recordContent' is list of messages. Each message is dict
                    with following elements:
                        {'header': {'protocolType', 'procedureType', 'messageType',
                                    'direction', 'second', 'serviceCellId',
                                    'quatMillisecond', 'messageTlvDataLength',
                                    'messageSequence', 'rawDataLength'
                                },
                        'tlvData', 'rawData'
                        }
        More detailed information see in the ZTE specificztions mentioned above.
    """

    #Parsing the Binnary File
    # https://docs.python.org/3/library/struct.html#struct.unpack
    # https://docs.python.org/3/library/struct.html#struct-format-strings
    # Byte      - B (1 byte)
    # WORD16    - H (2 bytes)
    # WORD32    - L (4 bytes)
    # WORD64    - Q (8 bytes)
    # Char[]    - s

    result = {'file': None, 'dataRecords': None}

    with open(file, 'rb') as f:
        #byte = f.read(36+16)
        ElementId, ElementMode, FileType, ElementVersion, FileStartTimestamp, FileEndTimestamp, FileRecordNumber, FileNo = struct.unpack('=HBB32sLLLL', f.read(52))
        ElementVersion = ElementVersion.decode().rstrip('\0')
        FileStartTimestamp = toDateTime(seconds=FileStartTimestamp)  #01.01.2000
        FileEndTimestamp = toDateTime(seconds=FileEndTimestamp)  #01.01.2000
        f.read(28)  #Reserved 28 bytes

        result['file'] = {'ElementId': ElementId, 'ElementMode': ElementMode, 'FileType': FileType, 'ElementVersion': ElementVersion,
                'FileStartTimestamp': FileStartTimestamp, 'FileEndTimestamp': FileEndTimestamp, 'FileRecordNumber': FileRecordNumber, 'FileNo': FileNo
        }

        if  FileRecordNumber > 0:
            dataRecords =list()
            for rec in range(FileRecordNumber):
                recordTlvData =''
                recordRawContent =''
                messages =list()
                recordLength, recordHeader_ueIdInfo_GlobalCallId, recordHeader_ueIdInfo_ImsiInformation_ImsiLength = struct.unpack('=HQB', f.read(11))
                f.read(1)  #Reserved 1 byte
                recordHeader_ueIdInfo_ImsiInformation_AccessCellId, imsi = struct.unpack('=H8s', f.read(10))
                recordHeader_ueIdInfo_ImsiInformation_ImsiElement = '{0}{1}{2}{3}{4}{5}{6}{7}{8}{9}{10}{11}{12}{13}{14}'.format(
                    ('{0:0>2x}'.format(imsi[0]))[0],
                    ('{0:0>2x}'.format(imsi[1]))[1], ('{0:0>2x}'.format(imsi[1]))[0],
                    ('{0:0>2x}'.format(imsi[2]))[1], ('{0:0>2x}'.format(imsi[2]))[0],
                    ('{0:0>2x}'.format(imsi[3]))[1], ('{0:0>2x}'.format(imsi[3]))[0],
                    ('{0:0>2x}'.format(imsi[4]))[1], ('{0:0>2x}'.format(imsi[4]))[0],
                    ('{0:0>2x}'.format(imsi[5]))[1], ('{0:0>2x}'.format(imsi[5]))[0],
                    ('{0:0>2x}'.format(imsi[6]))[1], ('{0:0>2x}'.format(imsi[6]))[0],
                    ('{0:0>2x}'.format(imsi[7]))[1], ('{0:0>2x}'.format(imsi[7]))[0]
                )
                (recordHeader_SourceId, recordHeader_RecordType, recordHeader_RecordTlvDataLength, recordHeader_MessageCount,
                    recordHeader_RecordContentLength, recordHeader_RecordSequence) = struct.unpack('=LBBHHH', f.read(12))

                #Add only data records which present in list filterByImsi or all records if list filterByImsi is empty
                if len(filterByImsi) == 0 or recordHeader_ueIdInfo_ImsiInformation_ImsiElement in filterByImsi:

                    if recordHeader_RecordTlvDataLength > 0:
                        recordTlvData = f.read(recordHeader_RecordTlvDataLength).hex()
                        #print('!!!!!!! WARNING !!!!!!!\nFile: {0}\nRecord {1} has TLV Data: {2}\n!!!!!!! WARNING !!!!!!!'.format(
                        #    file, rec, recordTlvData))

                    if recordHeader_MessageCount > 0:
                        if decodeRecordsContent:
                            for m in range(recordHeader_MessageCount):
                                (messageHeader_ProtocolType, messageHeader_ProcedureType, messageHeader_MessageType,
                                    messageHeader_Direction, messageHeader_Second, messageHeader_ServiceCellId,
                                    messageHeader_QuatMillisecond, messageHeader_MessageTlvDataLength,
                                    messageHeader_MessageSequence, messageHeader_RawDataLength) = struct.unpack('=BBBBLHBBHH', f.read(16))


                                messageTlvData = ''
                                if messageHeader_MessageTlvDataLength > 0:
                                    messageTlvData = f.read(messageHeader_MessageTlvDataLength).hex()
                                    #print('!!!!!!! WARNING !!!!!!!\nFile: {0}\nRecord {1} Message {2} has TLV Data: {3}\n!!!!!!! WARNING !!!!!!!'.format(
                                    #    file, rec, m, messageTlvData))

                                messageRawData = ''
                                if messageHeader_RawDataLength > 0:
                                    if saveMessageRawData:
                                        messageRawData = f.read(messageHeader_RawDataLength).hex()
                                    else:
                                        f.read(messageHeader_RawDataLength)

                                message = {'header': {'protocolType': messageHeader_ProtocolType,
                                                        'procedureType':messageHeader_ProcedureType,
                                                        'messageType':messageHeader_MessageType,
                                                        'direction':messageHeader_Direction,
                                                        'second': messageHeader_Second,
                                                        'serviceCellId':messageHeader_ServiceCellId,
                                                        'quatMillisecond':messageHeader_QuatMillisecond,
                                                        'messageTlvDataLength':messageHeader_MessageTlvDataLength,
                                                        'messageSequence':messageHeader_MessageSequence,
                                                        'rawDataLength':messageHeader_RawDataLength},
                                            'tlvData': messageTlvData, 'rawData': messageRawData
                                }
                                #from pprint import pprint
                                #pprint(message)
                                messages.append(message)
                        else:
                            recordRawContent = f.read(recordHeader_RecordContentLength).hex()

                    record = {'recordLength':recordLength, 'recordHeader':{
                                'ueIdInfo': {
                                    'GlobalCallId': recordHeader_ueIdInfo_GlobalCallId,
                                    'ImsiLength': recordHeader_ueIdInfo_ImsiInformation_ImsiLength,
                                    'AccessCellId': recordHeader_ueIdInfo_ImsiInformation_AccessCellId,
                                    'ImsiElement': recordHeader_ueIdInfo_ImsiInformation_ImsiElement
                                },
                                'SourceId': recordHeader_SourceId,
                                'RecordType': recordHeader_RecordType,
                                'RecordTlvDataLength': recordHeader_RecordTlvDataLength,
                                'MessageCount': recordHeader_MessageCount,
                                'RecordContentLength': recordHeader_RecordContentLength,
                                'RecordSequence': recordHeader_RecordSequence
                            },
                            'recordTlvData': recordTlvData, 'recordContent':messages, 'recordRawContent':recordRawContent}
                    #from pprint import pprint
                    #pprint(record)
                    dataRecords.append(record)
                else:
                    #Read the rest of the data record
                    f.read(recordHeader_RecordTlvDataLength + recordHeader_RecordContentLength)

                #Record end flag (const 0xEFFE (61438)
                byte = f.read(2)
                if byte != b'\xfe\xef':
                    print('!!!!!!! WARNING !!!!!!!\nFile: {0}\nRecord {1} has wrong Record end flag: {2}\n!!!!!!! WARNING !!!!!!!'.format(
                        file, rec, byte.hex()))

    result['dataRecords'] = dataRecords
    return result


def toDateTime(seconds: int, milliseconds=0) ->datetime:
    """
    Convert ZTE timestamp to Datetime type

    Parameters
    ----------
    seconds: int
        ZTE time in seconds

    milliseconds=0: int
        Add milliseconds if needed

    Returns
    -------
    datetime
        Returns datetime in Python format
    """

    dt = datetime(year=2000, month=1, day=1) + timedelta(seconds=seconds)  #01.01.2000
    if milliseconds != 0:
        dt += timedelta(milliseconds=milliseconds)

    return dt



class FstParser:

    def __init__(self):
        self.__fstfile = None
        self.__fstfileName = None
        self.__fstfileInfo = None


    def open(self, file: str) -> dict:
        self.__fstfileName = file

        self.__fstfile = open(file, 'rb')
        #byte = f.read(36+16)
        ElementId, ElementMode, FileType, ElementVersion, FileStartTimestamp, FileEndTimestamp, FileRecordNumber, FileNo = struct.unpack('=HBB32sLLLL', self.__fstfile.read(52))
        ElementVersion = ElementVersion.decode().rstrip('\0')
        FileStartTimestamp = toDateTime(seconds=FileStartTimestamp)  #01.01.2000
        FileEndTimestamp = toDateTime(seconds=FileEndTimestamp)  #01.01.2000
        self.__fstfile.read(28)  #Reserved 28 bytes

        self.__fstfileInfo =  {'ElementId': ElementId, 'ElementMode': ElementMode, 'FileType': FileType, 'ElementVersion': ElementVersion,
                'FileStartTimestamp': FileStartTimestamp, 'FileEndTimestamp': FileEndTimestamp, 'FileRecordNumber': FileRecordNumber, 'FileNo': FileNo
        }
        return self.__fstfileInfo


    def readRecords(self, decodeRecordsContent = True, saveMessageRawData = True, filterByImsi = list()) -> dict:
        for rec in range(self.__fstfileInfo['FileRecordNumber']):
            recordTlvData =''
            recordRawContent =''
            messages =list()
            recordLength, recordHeader_ueIdInfo_GlobalCallId, recordHeader_ueIdInfo_ImsiInformation_ImsiLength = struct.unpack('=HQB', self.__fstfile.read(11))
            self.__fstfile.read(1)  #Reserved 1 byte
            recordHeader_ueIdInfo_ImsiInformation_AccessCellId, imsi = struct.unpack('=H8s', self.__fstfile.read(10))
            recordHeader_ueIdInfo_ImsiInformation_ImsiElement = '{0}{1}{2}{3}{4}{5}{6}{7}{8}{9}{10}{11}{12}{13}{14}'.format(
                ('{0:0>2x}'.format(imsi[0]))[0],
                ('{0:0>2x}'.format(imsi[1]))[1], ('{0:0>2x}'.format(imsi[1]))[0],
                ('{0:0>2x}'.format(imsi[2]))[1], ('{0:0>2x}'.format(imsi[2]))[0],
                ('{0:0>2x}'.format(imsi[3]))[1], ('{0:0>2x}'.format(imsi[3]))[0],
                ('{0:0>2x}'.format(imsi[4]))[1], ('{0:0>2x}'.format(imsi[4]))[0],
                ('{0:0>2x}'.format(imsi[5]))[1], ('{0:0>2x}'.format(imsi[5]))[0],
                ('{0:0>2x}'.format(imsi[6]))[1], ('{0:0>2x}'.format(imsi[6]))[0],
                ('{0:0>2x}'.format(imsi[7]))[1], ('{0:0>2x}'.format(imsi[7]))[0]
            )
            (recordHeader_SourceId, recordHeader_RecordType, recordHeader_RecordTlvDataLength, recordHeader_MessageCount,
                recordHeader_RecordContentLength, recordHeader_RecordSequence) = struct.unpack('=LBBHHH', self.__fstfile.read(12))

            #Add only data records which present in list filterByImsi or all records if list filterByImsi is empty
            if len(filterByImsi) == 0 or recordHeader_ueIdInfo_ImsiInformation_ImsiElement in filterByImsi:
                if recordHeader_RecordTlvDataLength > 0:
                    recordTlvData = self.__fstfile.read(recordHeader_RecordTlvDataLength).hex()

                if recordHeader_MessageCount > 0:
                    if decodeRecordsContent:
                        for m in range(recordHeader_MessageCount):
                            (messageHeader_ProtocolType, messageHeader_ProcedureType, messageHeader_MessageType,
                                messageHeader_Direction, messageHeader_Second, messageHeader_ServiceCellId,
                                messageHeader_QuatMillisecond, messageHeader_MessageTlvDataLength,
                                messageHeader_MessageSequence, messageHeader_RawDataLength) = struct.unpack('=BBBBLHBBHH', self.__fstfile.read(16))

                            messageTlvData = ''
                            if messageHeader_MessageTlvDataLength > 0:
                                messageTlvData = self.__fstfile.read(messageHeader_MessageTlvDataLength).hex()

                            messageRawData = ''
                            if messageHeader_RawDataLength > 0:
                                if saveMessageRawData:
                                    messageRawData = self.__fstfile.read(messageHeader_RawDataLength).hex()
                                else:
                                    self.__fstfile.read(messageHeader_RawDataLength)

                            message = {'header': {'protocolType': messageHeader_ProtocolType,
                                                    'procedureType':messageHeader_ProcedureType,
                                                    'messageType':messageHeader_MessageType,
                                                    'direction':messageHeader_Direction,
                                                    'second': messageHeader_Second,
                                                    'serviceCellId':messageHeader_ServiceCellId,
                                                    'quatMillisecond':messageHeader_QuatMillisecond,
                                                    'messageTlvDataLength':messageHeader_MessageTlvDataLength,
                                                    'messageSequence':messageHeader_MessageSequence,
                                                    'rawDataLength':messageHeader_RawDataLength},
                                        'tlvData': messageTlvData, 'rawData': messageRawData
                            }
                            #from pprint import pprint
                            #pprint(message)
                            messages.append(message)
                    else:
                        recordRawContent = self.__fstfile.read(recordHeader_RecordContentLength).hex()

                record = {'recordLength':recordLength, 'recordHeader':{
                            'ueIdInfo': {
                                'GlobalCallId': recordHeader_ueIdInfo_GlobalCallId,
                                'ImsiLength': recordHeader_ueIdInfo_ImsiInformation_ImsiLength,
                                'AccessCellId': recordHeader_ueIdInfo_ImsiInformation_AccessCellId,
                                'ImsiElement': recordHeader_ueIdInfo_ImsiInformation_ImsiElement
                            },
                            'SourceId': recordHeader_SourceId,
                            'RecordType': recordHeader_RecordType,
                            'RecordTlvDataLength': recordHeader_RecordTlvDataLength,
                            'MessageCount': recordHeader_MessageCount,
                            'RecordContentLength': recordHeader_RecordContentLength,
                            'RecordSequence': recordHeader_RecordSequence
                        },
                        'recordTlvData': recordTlvData, 'recordContent':messages, 'recordRawContent':recordRawContent}
                #from pprint import pprint
                #pprint(record)
            else:
                #Read the rest of the data record
                self.__fstfile.read(recordHeader_RecordTlvDataLength + recordHeader_RecordContentLength)
                record = None

            #Record end flag (const 0xEFFE (61438)
            byte = self.__fstfile.read(2)
            if byte != b'\xfe\xef':
                print('!!!!!!! WARNING !!!!!!!\nFile: {0}\nRecord {1} has wrong Record end flag: {2}\n!!!!!!! WARNING !!!!!!!'.format(
                    file, rec, byte.hex()))
            if record != None:
                yield record



    def close(self):
        self.__fstfile.close()


if __name__ == '__main__':
    print('Module file_parsers.py is not main application')