#!/usr/bin/python3
import os
import csv
import socket
import glob
import domain_utils as du
import AndroidDataPrivacy.AppFinder as AppFinder
import AndroidDataPrivacy.Applications.AndroidNative as AndroidNative
import AndroidDataPrivacy.Applications.AppDefault as AppDefault
import AndroidDataPrivacy.Applications.FDroid as FDroid
import AndroidDataPrivacy.Applications.GSuite as GSuite
import AndroidDataPrivacy.Applications.Session as Session
import AndroidDataPrivacy.Applications.Signal as Signal
import AndroidDataPrivacy.Applications.Telegram as Telegram
import AndroidDataPrivacy.Applications.WhatsApp as WhatsApp
import AndroidDataPrivacy.Applications.Wire as Wire
import AndroidDataPrivacy.AnalysisFlow as AnalysisFlow
import AndroidDataPrivacy.Result as Result

from mitmproxy import flow
from mitmproxy.io import FlowReader

filenames = []
flows = []
results = []
appList = [
	'GSuite',
	'WhatsApp',
	'Telegram',
	'Session',
	'Wire',
	'Signal',
	'FDroid',
	'AppDefault',
	'AndroidNative',
	'Unknown']


def load_file(file_to_load):
	with open(file_to_load, 'rb') as fp:
		reader = FlowReader(fp)

		for HTTPFlow in reader.stream():
			new_flow = AnalysisFlow.AnalysisFlow()
			new_flow.import_raw_flow(HTTPFlow)
			new_flow.flowtype = HTTPFlow.type
			new_flow.user_agent = new_flow.get_user_agent()
			if new_flow.flowtype == 'http':
				# noinspection PyBroadException
				try:
					app = AppFinder.find_app(HTTPFlow, appList, str(new_flow.user_agent[1]))
					new_flow.app = app

				except TypeError:
					new_flow.app = 'Unknown'
				# noinspection PyBroadException
				try:
					new_flow.url = HTTPFlow.request.pretty_url
				except TypeError:
					new_flow.url = 'Unknown URL'
				flows.append(new_flow)
			# print(flow.request.url)
	return


def analyse_flow(flow_item):
	new_result = Result.Result(flow_item)
	new_result.app = 	check_app(flow_item)
	results.append(new_result)
	return


def check_flow(flow_item):
	if flow_item.app == 'GSuite' and 'GSuite' in appList:
		GSuite.checkBehavior(flow_item, results)
	if flow_item.app == 'FDroid' and 'FDroid' in appList:
		FDroid.checkBehavior(flow_item, results)
	if flow_item.app == 'Session' and 'Session' in appList:
		Session.checkBehavior(flow_item, results)
	if flow_item.app == 'Signal' and 'Signal' in appList:
		Signal.checkBehavior(flow_item, results)
	if flow_item.app == 'Telegram' and 'Telegram' in appList:
		Telegram.checkBehavior(flow_item, results)
	if flow_item.app == 'WhatsApp' and 'WhatsApp' in appList:
		WhatsApp.checkBehavior(flow_item, results)
	if flow_item.app == 'Wire' and 'Wire' in appList:
		Wire.checkBehavior(flow_item, results)
	if flow_item.app == 'AndroidNative' and 'AndroidNative' in appList:
		AndroidNative.checkBehavior(flow_item, results)
	if flow_item.app == 'AppDefault' and 'AppDefault' in appList:
		AppDefault.checkBehavior(flow_item, results)
	return


def check_app(flow_item):
	user_agent = str(flow_item.get_user_agent())
	app = ""
	if 'GSuite' in appList:
		for search_string in GSuite.partialUserAgents:
			x=user_agent.find(search_string)
			if(x==search_string):
				app = 'GSuite'
	if 'FDroid' in appList:
		for search_string in FDroid.partialUserAgents:
			x=user_agent.find(search_string)
			if(x==search_string):
				app = 'FDroid'
	if 'Session' in appList:
		for search_string in Session.partialUserAgents:
			x=user_agent.find(search_string)
			if(x==search_string):
				app = 'Session'
	if 'Signal' in appList:
		for search_string in Signal.partialUserAgents:
			x=user_agent.find(search_string)
			if(x==search_string):
				app = 'Signal'
	if 'Telegram' in appList:
		for search_string in Telegram.partialUserAgents:
			x=user_agent.find(search_string)
			if(x==search_string):
				app = 'Telegram'
	if 'WhatsApp' in appList:
		for search_string in WhatsApp.partialUserAgents:
			x=user_agent.find(search_string)
			if(x==search_string):
				app = 'WhatsApp'
	if 'Wire' in appList:
		for search_string in Wire.partialUserAgents:
			x=user_agent.find(search_string)
			if(x==search_string):
				app = 'Wire'
	if 'AndroidNative' in appList:
		for search_string in AndroidNative.partialUserAgents:
			x=user_agent.find(search_string)
			if(x==search_string):
				app = 'AndroidNative'
	return app


def analyze_all():
	count = 0
	for flow_item in flows:
		analyse_flow(flow_item)
		count = count + 1
	print('\n')
	print('flow count: ' + str(count) + ' Results: ' + str(len(results)))
	return


def save_results(log_results):
	save_file_name = os.path.splitext(filename)[0]
	save_file_name = os.path.basename(save_file_name)

	print("\nSaving to " + save_file_name)
	with open("Output/Stage1/" + save_file_name + '.csv', mode='w') as results_file:
		results_writer = csv.writer(results_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
		results_writer.writerow(['Application', 'URL', 'TLD', 'Source', 'UserAgent', 'Host', 'Destination', 'Info'])
		for result in log_results:
			try:
				host_string = str(socket.gethostbyaddr(result.get_source())[0])
			except:  # noinspection PyBroadException
				host_string = ''
			url_string = result.get_url();
			tld_string = du.get_etld1(url_string)
			info_string = result.get_info()
			results_writer.writerow([result.get_app(), url_string, tld_string,  result.get_source(), result.useragent,
									 host_string, result.get_destination(), info_string])


if __name__ == '__main__':
	filenames = sorted(glob.glob(r"Capture/*.cap"))
	for filename in filenames:
		results.clear()
		load_file(filename)
		analyze_all()
		save_results(results)
