import json
from strato.common.log import config as logconfig
import os
import datetime
import re
import calendar
import yaml
import logging
import time
from collections import defaultdict

FILEBEAT_CONFIG_FILE_PATH = 'tools/monitoring/filebeat.yml'
OUTPUT_PATH = os.path.join(logconfig.LOGS_DIRECTORY, 'exceptions.stratolog')
LOGS_WITH_COMMON_FORMAT = ['consul', 'nova', 'neutron', 'keystone']
LOGS_DISTRIBUTION = defaultdict(int)
LOGS_TYPES_FOR_ADJUSTMENT = list(LOGS_WITH_COMMON_FORMAT) + ['vm-console', 'mancala-bin']


def start(hosts):
    try:
        filebeatinstall.installFilebeat(hosts, FILEBEAT_CONFIG_FILE_PATH)
    except:
        logging.warning('Failed to install filebeat')


def stop(hosts):
    try:
        filebeatinstall.stopFilebeat(hosts)
        createExceptionFile(hosts)
        printLogsDistribution()
    except:
        logging.warning('Failed to create exception file')


def createExceptionFile(hosts):
    exceptions = []
    filebeatConfig = yaml.load(open(FILEBEAT_CONFIG_FILE_PATH, 'r').read())
    exceptionFileDir = filebeatConfig['output']['file']['path']
    exceptionFileBaseName = filebeatConfig['output']['file']['filename']
    for host in hosts:
        timeGap = _findTimezoneOffset(host)
        for fileName in _listAllExceptionFilesOnHost(host, exceptionFileDir, exceptionFileBaseName):
            try:
                filePath = os.path.join(exceptionFileDir, fileName)
                hostExceptions = host.ssh.ftp.getContents(filePath).strip().split('\n')
                exceptions.extend([_formaliseExceptionLog(line, host.name, timeGap) for line in hostExceptions])
                exceptions.extend(_getBeforeAndAfterRunLogs(host, timeGap))
            except:
                logging.warning('failed to collect exception log from %s' % host.name)
                continue
    try:
        sortedList = sorted(exceptions, key=lambda k: k['created'])
    except:
        logging.warning("Failed to parse some of the lines. Omitting the failed lines")
        sortedList = sorted([line for line in exceptions if line], key=lambda k: k['created'])
    with open(OUTPUT_PATH, 'w+') as f:
        f.write('\n'.join([json.dumps(entry) for entry in sortedList]))


def _formaliseExceptionLog(line, hostName, timeGap):
    try:
        parsedLine = json.loads(line)
        logType = parsedLine['type']
        if logType == 'stratolog':
            message = json.loads(parsedLine['message'])
        elif logType in LOGS_TYPES_FOR_ADJUSTMENT:
            message = _adjustLine(parsedLine, logType, timeGap)
        else:
            return line
        _addPropertyToMessage(message, 'host', hostName)
        _addPropertyToMessage(message, 'source', parsedLine['source'])
        collectStatistics(parsedLine['source'])
        return message
    except:
        return


def _addPropertyToMessage(logLine, propertyName, propertyValue):
    if type(logLine['args']) == dict:
        logLine['args'].update({propertyName: propertyValue})
        logLine['msg'] = ''.join([propertyName, ':%(', propertyName, ')s ', logLine['msg']])
    else:
        logLine['msg'] = ''.join([propertyName, ':', propertyValue, ' ', logLine['msg']])


def _adjustLine(line, logType, timeGap):
    # basic stratolog format to make other kinds of logs be able to be read with strato-log
    stratologFormat = {'threadName': 'unknown', 'name': 'root', 'thread': 000000000000000, 'process': 00000,
                       'args': {}, 'module': logType, 'funcName': 'unknown', 'levelno': 100, 'processName': logType,
                       'levelname': 'ERROR', "exc_text": None, "lineno": 225}
    if logType in LOGS_WITH_COMMON_FORMAT:
        stratologFormat.update(_getMessageData(line, timeGap))
    elif logType == 'journalctl':
        stratologFormat.update(_parseJournalLine(line, timeGap))
    elif logType == 'vm-console':
        stratologFormat.update(_parseVmConsoleLine(line))
    elif logType == 'mancala-bin':
        stratologFormat.update(_parseMancalaBinLine(line))

    # at this point internal messages must be fully formatted. Percent escape added for the strato-log parsing stage
    # where random percents may fail the string substitution

    stratologFormat['msg'] = stratologFormat['msg'].replace('%', '%%')
    return stratologFormat


# to add parse log type you'll need to return dict with 'msg' field with error log to be displayed,
# 'created' with epoch time of the log, 'pathname' with path to the log and 'filename' with name of the log file


def _getMessageData(line, timeGap):
    msg, timestamp = seperateTimestamp(line['message'])
    timestamp = timestamp.replace('-', '/')
    return {'msg': msg, 'created': translateToEpoch(timestamp) + timeGap, 'pathname': line['source'],
            'filename': os.path.split(line['source'])[-1]}


# if adding journalctl logs, please run the log with "-o short-iso" option

def _parseJournalLine(line, timeGap):
    epochTime = translateToEpoch(line.split(' ')[0], format="%Y-%m-%dT%H:%M:%S-%f") + timeGap
    msg = ' '.join(line.split(' ')[1:])
    return {'msg': msg, 'created': epochTime, 'pathname': 'journalctl',
            'filename': 'journalctl', "levelname": "WARNING"}


def _parseVmConsoleLine(line):
    # vm console does not have exact time signatures, rather is used to verify if certain message occurred
    # while using timestamp of filebeat to see when the line was logged (~10 sec delay)
    epochTime = translateToEpoch(line["@timestamp"], format="%Y-%m-%dT%H:%M:%S.%fZ")
    return {'msg': line['message'], 'created': epochTime, 'pathname': 'vm-console',
            'filename': 'vm-console', 'levelname': 'ERROR'}


def _parseMancalaBinLine(line):
    splitLine = line['message'].split(';')
    pathname = line['source']
    filename = os.path.basename(pathname)
    epochTime = float(splitLine[0])
    msg = ';'.join(splitLine[1:]).strip()

    return {'msg': msg, 'created': epochTime, 'pathname': pathname,
            'filename': filename, 'levelname': 'ERROR'}


def seperateTimestamp(message, format='(\d{4}[-/]\d{2}[-/]\d{2} \d{2}[:]\d{2}[:]\d{2})'):
    # default regex matches date pattern in format "yyyy/dd/mm hh:mm:ss"
    dateRegex = re.compile(format)
    date = dateRegex.findall(message.strip())[0]
    # remove everything at the beggining of the line that isn't letters and "[" (for consul logs)
    msg = '\n'.join([re.sub("^[^a-zA-Z\[]*", "                ", line) for line in message.split('\n')])
    return msg, date


def translateToEpoch(timeStamp, format="%Y/%m/%d %H:%M:%S"):
    timeObject = datetime.datetime.strptime(timeStamp, format)
    return calendar.timegm(timeObject. timetuple())


# use _findTimezoneOffset if the log you're using is using localtime and not UTC

def _findTimezoneOffset(host):
    try:
        return int(host.seed.runCallable(getTimezoneOffset)[0])
    except:
        logging.warning('Failed to calculate timezone offset on %s' % host.name)
        return 0


def getTimezoneOffset():
    return time.timezone if (time.localtime().tm_isdst == 0) else time.altzone


def _listAllExceptionFilesOnHost(host, fileDir, fileBaseName):
    try:
        fileNames = host.seed.runCallable(_listDirs, fileDir)[0]
        if fileNames:
            return [fileName for fileName in fileNames if str(fileName).startswith(fileBaseName)]
    except:
        logging.warning('Failed to get list of files from %s' % host.name)
        return []


def _listDirs(path):
    return os.listdir(path)


def collectStatistics(filepath):
    logSource = os.path.basename(filepath)
    LOGS_DISTRIBUTION[logSource] += 1


def printLogsDistribution():
    if LOGS_DISTRIBUTION:
        logging.info("Logs distribution:")
        for logType, logCount in LOGS_DISTRIBUTION.iteritems():
            logging.info("%(logType)s: %(logCount)s" % dict(logType=logType,
                                                            logCount=logCount))


def _getBeforeAndAfterRunLogs(host, timeGap):
    try:
        outputLogs = _getLogFromJournal("BEFORE RUN", host) + _getLogFromJournal("AFTER RUN", host)
        return [_adjustLine(line, 'journalctl', timeGap) for line in outputLogs if line]
    except:
        return


def _getLogFromJournal(regex, host):
    try:
        return host.ssh.run.script('journalctl -o short-iso | grep "%s"' % regex).strip().split('\n')
    except:
        return []
