#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
#
# This script is licensed under GNU GPL version 2.0 or above
# (c) Antonio J. Delgado 2021
# Python script to get RSS feeds into your IMAP mail

import sys
import os
import re
import hashlib
import json
import time
import imaplib
import email
from email import message
import urllib

import yaml
import requests
import click
import click_config_file
import logging
from logging.handlers import SysLogHandler
from defusedxml.ElementTree import fromstring

class feed2imap():

    def __init__(self, debug_level='INFO', feeds_file=None, log_file=None, default_email=None, disable_ssl_verification=False, include_images=True, feeds=None, cache_file=None):
        ''' Initialize feed2imap '''
        self.debug_level=debug_level
        if log_file is None:
            log_file=os.path.join(os.environ['HOME'], 'log', 'feed2imap.log')
        self._get_log(log_file=log_file)
        if cache_file is None:
            cache_file=os.path.join(os.environ['HOME'], '.feed2imap.cache')
        self.cache = list()
        self.cache_file = cache_file
        if feeds_file is not None:
            with open(feeds_file, 'r') as ffile:
                content = ffile.read()
            feeds_file_content=yaml.load(content, Loader=yaml.CLoader)
            self.feeds = feeds_file_content['feeds']
        self.default_email=default_email
        self.disable_ssl_verification=disable_ssl_verification
        self.include_images=include_images
        self._load_cache()
        items = self._process_feeds()
        self._save_cache()
        self.connection = None
        self._save_items(items)

    def _connect(self, target):
        ''' Connect to the IMAP target '''
        imap_target = self._parse_imap_target(target)
        self.imap_target = imap_target
        if imap_target:
            if imap_target['protocol'] == "imap":
                self._log.debug(f"Unsecure IMAP connection to '{imap_target['server']}:{imap_target['port']}'")
                self.connection = imaplib.IMAP4(imap_target['server'], imap_target['port'])
            else:
                self._log.debug(f"Secure IMAP connection to '{imap_target['server']}:{imap_target['port']}'")
                self.connection = imaplib.IMAP4_SSL(imap_target['server'], imap_target['port'])
            try:
                self.connection.login(imap_target['username'], imap_target['password'])
            except imaplib.IMAP4.error as e:
                self._log.error(f"Error login as '{imap_target['username']}' to '{imap_target['server']}:{imap_target['port']}'. {e}")
                return False
            self._log.debug(f"Logged in as '{imap_target['username']}'...")

            if not self._check_mailbox_exists(imap_target['mbox']):
                if not self._create_mailbox(imap_target['mbox']):
                    return False
                else:
                    return True
            else:
                return True
        else:
            self._log.error(f"Unable to parse target '{target}'")
            return False

    def _parse_imap_target(self, target):
        match = re.match(r"^([iI][mM][aA][pP][sS]?)://([^:]*):([^@]*)@([^\/]*)\/(.*)$", target)
        if match is None:
            return False
        else:
            imap_target = dict()
            imap_target['protocol'] = match.group(1)
            self._log.debug(f"Protocol for IMAP: {imap_target['protocol']}")
            imap_target['username'] = urllib.parse.unquote(match.group(2))
            self._log.debug(f"User for IMAP: {imap_target['username']}")
            imap_target['password'] = urllib.parse.unquote(match.group(3))
            imap_target['hidden_password'] = "*" * len(imap_target['password'])
            self._log.debug(f"Password for IMAP: {imap_target['hidden_password']}")
            imap_target['server'] = match.group(4)
            self._log.debug(f"Server for IMAP: {imap_target['server']}")
            if match.lastindex > 5:
                imap_target['port'] = match.group(5)
                self._log.debug(f"Port for IMAP: {imap_target['port']}")
                imap_target['mbox'] = match.group(6)
                self._log.debug(f"Mail box for IMAP: {imap_target['mbox']}")
            elif match.lastindex < 6:
                imap_target['mbox'] = match.group(5)
                self._log.debug(f"Mail box for IMAP: {imap_target['mbox']}")
                if imap_target['protocol'] == 'imap':
                    imap_target['port'] = 143
                else:
                    imap_target['port'] = 993
            imap_target['hidden_target'] = "%s:%s@%s:%s/%s" % (
                imap_target['username'],
                imap_target['hidden_password'],
                imap_target['server'],
                imap_target['port'],
                imap_target['mbox']
            )
            return imap_target

    def _create_mailbox(self, mailbox):
        result = self.connection.create(mailbox)
        if result[0] == "NO":
            error_message = result[1][0].decode('utf-8')
            self._log.error(f'Error creating mailbox {mailbox}. {error_message}')
            return False
        else:
            self.connection.expunge()
            self._log.debug(f'Created mailbox {mailbox}')
            return True


    def _check_mailbox_exists(self, mailbox):
        result = self.connection.select(mailbox=mailbox, readonly=False)
        self._log.debug(f"Checking mailbox {mailbox} returned: {result}")
        if result[0] == "NO":
            self._log.debug(f"Mailbox {mailbox} doesn't exist.")
            return False
        else:
            self._log.debug(f"Mailbox {mailbox} exist.")
            return True


    def _save_items(self, items):
        ''' Save the items in their IMAP folder '''
        for target in items.keys():
            # Connect to item['target']
            if self._connect(target):
                if self.connection:
                    # Iterate over all items
                    for item in items[target]:
                        # Save items in target
                        self._log.debug(f"Adding item/message '{item['md5']}'...")
                        message = str(self._compose_message(item)).encode('utf-8')
                        result = self.connection.append(self.imap_target['mbox'],"", imaplib.Time2Internaldate(time.time()), message)
                        if result[0] == 'NO':
                            error_message = result[1][0].decode('utf-8')
                            self._log.error(f"Error adding item/message to {self.imap_target['hidden_target']}. IMAP error: {error_message}")
                        else:
                            self._log.debug('Added successfully.')
                else:
                    self._log.error(f"Connection failed.")
            else:
                self._log.error(f"Connection failed.")

    def _compose_message(self, item):
        new_message = email.message.Message()
        new_message.set_unixfrom('satheesh')
        title = item.get('title', '<no-title>')
        description = item.get('description', '')
        new_message['Subject'] = title
        new_message['From'] = self.default_email
        new_message['To'] = self.default_email
        body = '<HTML><BODY>\r\n'
        if 'link' in item:
            body += f"<H1>Title: <A HREF='{item['link']}'>{title}</A></H1>\r\n"
        else:
            body += f"<H1>Title: {title}</H1>\r\n"
        body += f"<H2>Description:</H2>\r\n{description}</BR>\r\n"

        item.pop('target')
        item.pop('link')
        item.pop('title')
        item.pop('description')
        payload = yaml.dump(item, Dumper=yaml.CDumper).encode('utf-8').replace(b'\n', b'<BR>').decode('utf-8')
        body += f"Payload:\r\n</BR>{payload}</BR>\r\n"
        body += "</BODY></HTML>\r\n"
        new_message.set_payload(body)
        return new_message

    def _save_cache(self):
        ''' Save the cached MD5 hashes of items downloaded '''
        with open(self.cache_file, 'w') as cache_f:
            cache_f.write(yaml.dump(self.cache, Dumper=yaml.CDumper))

    def _load_cache(self):
        ''' Load the MD5 hashes of items downloaded '''
        if not os.path.exists(self.cache_file):
            return True
        else:
            temp_cache=None
            with open(self.cache_file, 'r') as cache_f:
                temp_cache=yaml.load(cache_f.read(), Loader=yaml.CLoader)
            if temp_cache is not None:
                self.cache=temp_cache
        return True

    def _process_feeds(self):
        ''' Process all feeds provided '''
        items = dict()
        for feed in self.feeds:
            for item in self._get_feeds(feed):
                if item['target'] not in items:
                    items[item['target']] = list()
                items[item['target']].append(item)
        return items

    def _get_feeds(self, feed=None):
        ''' Process a feed and return an list of items '''
        if feed is not None:
            name = feed['name']
            url = feed['url']
            target = feed['target']
            self._log.debug(f"Getting feed '{name}' with URL '{url}'...")
            content = requests.get(url)
            element_tree = fromstring(content.text)
            items = list()
            for iter_item in element_tree.findall('{http://purl.org/rss/1.0/}item'):
                item = dict()
                item['name'] = name
                item['target'] = target
                md5sum = hashlib.md5()
                for iter_subitem in iter_item:
                    field = re.sub("{.*}", "", iter_subitem.tag)
                    value = iter_subitem.text
                    md5sum.update(f"{field}:{value}".encode('utf-8'))
                    #self._log.debug(f"Found field '{field}' with value '{value}'")
                    if field in item:
                        if isinstance(item[field], str):
                            self._log.debug(f"Field '{field}' is present in this item, creating a list")
                            old_value = item[field]
                            item[field] = list()
                            item[field].append(old_value)
                        elif isinstance(item[field], list):
                            self._log.debug(f"Field '{field}' is present in this item and it's a list, adding new value.")
                            item[field].append(value)
                    else:
                        item[field] = value
                item['md5'] = md5sum.hexdigest()
                if item['md5'] not in self.cache:
                    items.append(item)
                    self.cache.append(item['md5'])
                else:
                    self._log.debug('Item already downloaded')
            #print(yaml.dump(items, Dumper=yaml.CDumper))
            return items
                

    def _get_log(self, log_file=None):
        ''' Create the _log object for logging to syslog, standard output and file '''
        self._log = logging.getLogger("feed2imap")
        self._log.setLevel(logging.DEBUG)

        sysloghandler = SysLogHandler()
        sysloghandler.setLevel(logging.DEBUG)
        self._log.addHandler(sysloghandler)

        streamhandler = logging.StreamHandler(sys.stdout)
        streamhandler.setLevel(logging.getLevelName(self.debug_level))
        self._log.addHandler(streamhandler)

        if  log_file is None:
            if not os.path.exists(os.path.dirname(log_file)):
                os.path.mkdir(os.path.dirname(log_file))
            filehandler = logging.handlers.RotatingFileHandler(log_file, maxBytes=102400000)
            # create formatter
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            filehandler.setFormatter(formatter)
            self._log.addHandler(filehandler)


@click.command()
@click.option(
    "--debug-level",
    default="INFO",
    type=click.Choice(
        ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"],
        case_sensitive=False,
    ),
    help="Debug level.",
)
@click.option('--feeds-file', '-f', help='File in YAML with the information of the feeds.')
@click.option('--log-file','-l', help="File to store all log information.")
@click.option('--default-email','-e', default='feed2imap@localhost', help="Email address for the sender of the feed items.")
@click.option('--disable-ssl-verification','-n', is_flag=True, help="Disable SSL verification for the IMAP server certificate.")
@click.option('--include-images','-i', is_flag=True, help='Include images from feed items.')
@click.option('--feeds', '-f', multiple=True, help='Feed item in JSON format.')
@click.option('--cache-file', '-c', help='Cache file to store downloaded items.')
def __main__(debug_level, feeds_file, log_file, default_email, disable_ssl_verification, include_images, feeds, cache_file):
    ''' Wrapper function for feed2imap '''
    f2i=feed2imap(debug_level, feeds_file, log_file, default_email, disable_ssl_verification, include_images, feeds, cache_file)
    return True

if __name__ == "__main__":
    __main__()
