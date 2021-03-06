import AndroidDataPrivacy.AnalysisFlow as Flow
import AndroidDataPrivacy.Result as Result
import AndroidDataPrivacy.Applications.AppDefault as AppDefault

urls = ['http://ns.adobe.com/xap/1.0/',
								'http://schemas.android.com/apk/res-auto',
								'http://schemas.android.com/apk/res/android',
								'http://schemas.microsoft.com/DRM/2007/03/protocols/AcquireLicense',
								'http://www.gstatic.com/android/hangouts/hangouts_mms_ua_profile.xml',
								'http://www.w3.org/2001/SMIL20/Language',
								'http://www.w3.org/ns/ttml#parameter',
								'https://accounts.google.com/o/oauth2/revoke?token=',
								'https://android.clients.google.com/backup',
								'https://android.clients.google.com/cdn',
								'https://android.clients.google.com/cdn2',
								'https://android.clients.google.com/directory',
								'https://android.clients.google.com/service',
								'https://android.clients.google.com/storage',
								'https://aomedia.org/emsg/ID3',
								'https://api.backup.signal.org',
								'https://api.directory.signal.org',
								'https://cdn.signal.org',
								'https://cdn.sstatic.net',
								'https://cdn2.signal.org',
								'https://clients3.google.com/backup',
								'https://clients3.google.com/cdn',
								'https://clients3.google.com/cdn2',
								'https://clients3.google.com/directory',
								'https://clients3.google.com/service',
								'https://clients3.google.com/storage',
								'https://clients4.google.com/backup',
								'https://clients4.google.com/cdn',
								'https://clients4.google.com/cdn2',
								'https://clients4.google.com/directory',
								'https://clients4.google.com/service',
								'https://clients4.google.com/storage',
								'https://developer.apple.com/streaming/emsg-id3',
								'https://github.githubassets.com',
								'https://inbox.google.com/backup',
								'https://inbox.google.com/cdn',
								'https://inbox.google.com/cdn2',
								'https://inbox.google.com/directory',
								'https://inbox.google.com/service',
								'https://inbox.google.com/storage',
								'https://maps.google.com/maps',
								'https://open.scdn.co',
								'https://pinterest.com',
								'https://plus.google.com/',
								'https://sfu.staging.voip.signal.org',
								'https://sfu.test.voip.signal.org',
								'https://sfu.voip.signal.org',
								'https://signalcaptchas.org/challenge/generate.html',
								'https://storage.signal.org',
								'https://textsecure-service.whispersystems.org',
								'https://www.google.ae/backup',
								'https://www.google.ae/cdn',
								'https://www.google.ae/cdn2',
								'https://www.google.ae/directory',
								'https://www.google.ae/service',
								'https://www.google.ae/storage',
								'https://www.google.com.eg/backup',
								'https://www.google.com.eg/cdn',
								'https://www.google.com.eg/cdn2',
								'https://www.google.com.eg/directory',
								'https://www.google.com.eg/service',
								'https://www.google.com.eg/storage',
								'https://www.google.com.om/backup',
								'https://www.google.com.om/cdn',
								'https://www.google.com.om/cdn2',
								'https://www.google.com.om/directory',
								'https://www.google.com.om/service',
								'https://www.google.com.om/storage',
								'https://www.google.com.qa/backup',
								'https://www.google.com.qa/cdn',
								'https://www.google.com.qa/cdn2',
								'https://www.google.com.qa/directory',
								'https://www.google.com.qa/service',
								'https://www.google.com.qa/storage',
								'https://www.google.com/backup',
								'https://www.google.com/cdn',
								'https://www.google.com/cdn2',
								'https://www.google.com/directory',
								'https://www.google.com/service',
								'https://www.google.com/storage',
								'https://www.googleapis.com/auth/games',
								'https://www.googleapis.com/auth/games_lite',
								'https://www.redditstatic.com',
								'https://x']

partialURLs = []

userAgents = ['org.thoughtcrime.securesms', ]

partialUserAgents = ['Signal']


def checkBehavior(flow, results):
	if flow.get_request_type() == 'GET':
		analyzeGetRequest(flow, results)
	if flow.get_request_type() == 'POST':
		analyzePostRequest(flow, results)
	if flow.get_request_type() == 'HEAD':
		analyzePostRequest(flow, results)
	if flow.get_request_type() == 'PUT':
		analyzePutRequest(flow, results)
	if flow.get_request_type() == 'DELETE':
		analyzeDeleteRequest(flow, results)
	return

def analyzeGetRequest(flow, results):
	checkGetURL(flow, results)
	checkRequestHeaders(flow, flow.get_request_headers(), results)
	AppDefault.checkRequestHeadersDefault(flow, flow.get_request_headers(), results)
	checkResponseHeaders(flow, flow.get_response_headers(), results)
	AppDefault.checkResponseHeadersDefault(flow, flow.get_response_headers(), results)
	AppDefault.analyzeGetRequestDefault(flow, results)


def analyzePostRequest(flow, results):
	checkPostURL(flow, results)
	checkRequestHeaders(flow, flow.get_request_headers(), results)
	AppDefault.checkRequestHeadersDefault(flow, flow.get_request_headers(), results)
	checkResponseHeaders(flow, flow.get_response_headers(), results)
	AppDefault.checkResponseHeadersDefault(flow, flow.get_response_headers(), results)
	AppDefault.analyzePostRequestDefault(flow, results)


def analyzeHeadRequest(flow, results):
	checkHeadURL(flow, results)
	checkRequestHeaders(flow, flow.get_request_headers(), results)
	AppDefault.checkRequestHeadersDefault(flow, flow.get_request_headers(), results)
	checkResponseHeaders(flow, flow.get_response_headers(), results)
	AppDefault.checkResponseHeadersDefault(flow, flow.get_response_headers(), results)
	AppDefault.analyzeHeadRequestDefault(flow, results)


def analyzePutRequest(flow, results):
	checkPutURL(flow, results)
	checkRequestHeaders(flow, flow.get_request_headers(), results)
	AppDefault.checkRequestHeadersDefault(flow, flow.get_request_headers(), results)
	checkResponseHeaders(flow, flow.get_response_headers(), results)
	AppDefault.checkResponseHeadersDefault(flow, flow.get_response_headers(), results)
	AppDefault.analyzePutRequestDefault(flow, results)


def analyzeDeleteRequest(flow, results):
	checkDeleteURL(flow, results)
	checkRequestHeaders(flow, flow.get_request_headers(), results)
	AppDefault.checkRequestHeadersDefault(flow, flow.get_request_headers(), results)
	checkResponseHeaders(flow, flow.get_response_headers(), results)
	AppDefault.checkResponseHeadersDefault(flow, flow.get_response_headers(), results)
	AppDefault.analyzeDeleteRequestDefault(flow, results)


def checkRequestHeaders(flow, headers, results):
	return None


def checkResponseHeaders(flow, headers, results):
	return None


def checkGetURL(flow, results):
	type_string = flow.get_request_type()
	info_string = flow.get_url()
	results.append(Result.Result(flow, type_string, info_string))
	return


def checkPostURL(flow, results):
	type_string = flow.get_request_type()
	info_string = flow.get_url()
	results.append(Result.Result(flow, type_string, info_string))
	return


def checkHeadURL(flow, results):
	return None


def checkPutURL(flow, results):
	return None


def checkDeleteURL(flow, results):
	return None
