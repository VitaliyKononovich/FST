#!/usr/bin/env python3
"""
This module contains the functions for parsing dictionary for FST and functions
for searching in the dictionary
"""
import csv
import json

def load_dictionary_csv(file: str, conv_to_int_list: list) -> list:
    """
    Load dictionary from the csv file and convert required keys values to int

    Parameters
    ----------
    file: str
        Full path to csv-file

    conv_to_int_list: list
        List of the keys which values has to be converted to int

    Returns
    -------
    list
        Returns dictionary wich contains list of dictionay elements
    """

    dictionary = list()
    with open(file, newline='') as csvfile:
        reader = csv.DictReader(csvfile, delimiter=',')
        dictionary = [{k: v for k, v in row.items()} for row in reader]

    for item in dictionary:
        for k in conv_to_int_list:
           item[k] = int(item[k])

    return dictionary


def load_dictionary_json(file: str) -> list:
    """
    Load dictionary from the json file

    Parameters
    ----------
    file: str
        Full path to csv-file

    Returns
    -------
    list
        Returns dictionary wich contains list of dictionay elements
    """

    s = None
    with open(file) as f:
        s = f.read().replace('\n', '').replace('\t', ' ')
    return json.loads(s)


def search_for_message(dict_messages: list, dict_protocols: list, protocolType: int, procedureType: int, messageType: int) -> dict:
    """
    Search and return text information about the message/procedure/protocol
    based on thier IDs

    Parameters
    ----------
    dict_messages: list
        Reference to the Messages dictionary

    dict_protocols: list
        Reference to the Protocols dictionary

    protocolType: int
        Protocol type ID

    procedureType: int
        Procedure type ID

    messageType: int
        Message type ID

    Returns
    -------
    dict
        Returns dictionary wich contains names for message/procedure/protocol
        if they are exist:
            {'protocolName': '?', 'procedureName': '', 'messageName': ''}

    """

    msg = {'protocolName': '?', 'procedureName': '', 'messageName': ''}
    for message in dict_messages:
        if message['protocolType'] == protocolType and message['procedureType'] == procedureType and message['messageType'] == messageType:
            msg['messageName'] = message['messageName']
            break
    for protocol in dict_protocols:
        if protocol['protocolType'] ==  protocolType:
            msg['protocolName'] = protocol['protocolName']
            for procedure in protocol['procedures']:
                if procedure['procedureType'] == procedureType:
                    msg['procedureName'] = procedure['procedureName']
                    break
            break
    """if msg['messageName'] == '':
        print('{0}\t{1}\t{2}'.format(protocolType, procedureType, messageType))"""

    return msg


def search_for_direction(dict_directions: list, direction: int) -> str:
    """
    Search for direction in Ditections dictionary based on direction ID

    Parameters
    ----------
    dict_directions: list
        Reference to the Directions dictionary

    direction: int
        Direction ID

    Returns
    -------
    str
        Text releted fo the direction

    """

    d = '?'
    for dir in dict_directions:
        if dir['id'] == direction:
            d =  dir['value']
            break
    return d


def search_for_pcap_data(dict_pcap: list, protocolType: int, direction: int, procedureType: int) -> dict:

    d = None
    for item in dict_pcap:
        if item['protocolType'] == protocolType:
            d =  {'protocol': item['protocol'], 'pcap_data': None}
            for dir in item['dirs']:
                if dir['dir'] == direction:
                    if (protocolType == 102 or protocolType == 103 or protocolType == 104
                            or protocolType == 152 or protocolType == 153):
                        d['pcap_data'] = dir['pcap_data']
                    elif  protocolType == 101 or protocolType == 151:
                        for proc in dir['procedures']:
                            if proc['procedureType'] == procedureType:
                                d['pcap_data'] =  proc['pcap_data']
                                break
                    break
            break

    return d


if __name__ == '__main__':
    print('Module dict_parsers.py is not main application')



