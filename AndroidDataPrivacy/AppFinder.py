# import AndroidDataPrivacy.AnalysisFlow as AnalysisFlow
# import AndroidDataPrivacy.Result as Result


def find_app(flow, app_list):
	# requestHeaders = flow.get_request_headers()
	# url = flow.raw_flow.request.pretty_host
	# flow.raw_flow.request.user
	useragent = flow.get_user_agent()
	useragent_string = str(useragent[1])
	flow.user_agent = useragent_string
	app = ''

	for application in app_list:
		# print('app:\t'+application.lower() + '\tUser Agent String\t'+useragentstring + '\n')
		found = useragent_string.find(application.lower())
		if 1 <= found:
			app = application
		else:
			app = ''
	flow.app = app
	return app


def identify_user_agent(agent, app_list):
	if 'AndroidNative' in app_list:
		import AndroidDataPrivacy.Applications.AndroidNative as AndroidNative
		if agent in AndroidNative.userAgents:
			return 'AndroidNative'
		for item in AndroidNative.partialUserAgents:
			if agent.find(item) > -1:
				return 'AndroidNative'

	if 'GSuite' in app_list:
		import AndroidDataPrivacy.Applications.GSuite as GSuite
		if agent in GSuite.userAgents:
			return 'GSuite'
		for item in GSuite.partialUserAgents:
			if agent.find(item) > -1:
				return 'GSuite'

	if 'Session' in app_list:
		import AndroidDataPrivacy.Applications.Session as Session
		if agent in Session.userAgents:
			return 'Session'
		for item in Session.partialUserAgents:
			if agent.find(item) > -1:
				return 'Session'

	if 'Signal' in app_list:
		import AndroidDataPrivacy.Applications.Signal as Signal
		if agent in Signal.userAgents:
			return 'Signal'
		for item in Signal.partialUserAgents:
			if agent.find(item) > -1:
				return 'Signal'

	if 'Telegram' in app_list:
		import AndroidDataPrivacy.Applications.Telegram as Telegram
		if agent in Telegram.userAgents:
			return 'Telegram'
		for item in Telegram.partialUserAgents:
			if agent.find(item) > -1:
				return 'Telegram'

	if 'WhatsApp' in app_list:
		import AndroidDataPrivacy.Applications.WhatsApp as WhatsApp
		if agent in WhatsApp.userAgents:
			return 'WhatsApp'
		for item in WhatsApp.partialUserAgents:
			if agent.find(item) > -1:
				return 'WhatsApp'

	if 'Wire' in app_list:
		import AndroidDataPrivacy.Applications.Wire as Wire
		if agent in Wire.userAgents:
			return 'Wire'
		for item in Wire.partialUserAgents:
			if agent.find(item) > -1:
				return 'Wire'

	return 'Unknown'


def identify_uniform_resource_locator(flow, url, app_list):
	if 'AndroidNative' in app_list:
		import AndroidDataPrivacy.Applications.AndroidNative as AndroidNative
		if url in AndroidNative.urls:
			return 'AndroidNative'
		for item in AndroidNative.partialURLs:
			if url.find(item) > -1:
				return 'AndroidNative'

	if 'GSuite' in app_list:
		import AndroidDataPrivacy.Applications.GSuite as GSuite
		if url in GSuite.urls:
			return 'GSuite'
		for item in GSuite.partialURLs:
			if url.find(item) > -1:
				return 'GSuite'

	if 'Session' in app_list:
		import AndroidDataPrivacy.Applications.Session as Session
		if url in Session.urls:
			return 'Session'
		for item in Session.partialURLs:
			if url.find(item) > -1:
				return 'Session'

	if 'Signal' in app_list:
		import AndroidDataPrivacy.Applications.Signal as Signal
		if url in Signal.urls:
			return 'Signal'
		for item in Signal.partialURLs:
			if url.find(item) > -1:
				return 'Signal'

	if 'Telegram' in app_list:
		import AndroidDataPrivacy.Applications.Telegram as Telegram
		if url in Telegram.urls:
			return 'Telegram'
		for item in Telegram.partialURLs:
			if url.find(item) > -1:
				return 'Telegram'

	if 'Wire' in app_list:
		import AndroidDataPrivacy.Applications.Wire as Wire
		if url in Wire.urls:
			return 'Wire'
		for item in Wire.partialURLs:
			if url.find(item) > -1:
				return 'Wire'

	if url[:21] == 'https://api.branch.io':
		temp = flow.requestContent
		temp = temp[temp.find('"cd": {'):]
		temp = temp[:temp.find('}')]
		temp = temp[temp.find('"pn": "')+7:]
		temp = temp[:temp.find('"')]
		if temp[:10] == 'com.reddit':
			return 'Reddit'

	return ''
