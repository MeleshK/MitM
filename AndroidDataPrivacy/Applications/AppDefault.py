import AndroidDataPrivacy.AnalysisFlow as Flow
import AndroidDataPrivacy.Result as Result


def checkBehavior(flow, results):
    if (flow.get_request_type() == 'GET'):
        analyzeGetRequestDefault(flow, results)
    if (flow.get_request_type() == 'POST'):
        analyzePostRequestDefault(flow, results)
    if (flow.get_request_type() == 'HEAD'):
        analyzeHeadRequestDefault(flow, results)
    if (flow.get_request_type() == 'PUT'):
        analyzePutRequestDefault(flow, results)
    checkRequestHeadersDefault(flow, flow.get_request_headers(), results)
    checkResponseHeadersDefault(flow, flow.get_request_headers(), results)
    return


def analyzeGetRequestDefault(flow, results):
    url = flow.get_url()
    if (0 == checkFlowResults('IP Address', results)):
        info = flow.get_address()
        type_string = 'IP Address'
        results.append(Result.Result(flow, type_string, info))

    if (url.find('https://s2s.singular.net/api') == 0):
        flow.source = 'Singular.net'

        if (flow.requestContent.find('a:') > -1):
            if (findFormEntry(flow.requestContent, 'a') == 'linkedin'):
                flow.source = flow.source + ' LinkedIn'

        if (flow.requestContent.find('bd:') > -1):
            type_string = 'System Info: Build'
            info = findFormEntry(flow.requestContent, 'bd')
            results.append(Result.Result(flow, type_string, info))

    elif (url.find('https://secure-dcr.imrworldwide.com/cgi-bin/cfg') == 0):
        flow.source = findFormEntry(flow.requestContent, 'bid')
        if (flow.source == 'com.hulu.plus'):
            flow.source = 'Hulu'

            type_string = 'System Info: App GUID'
            info = findFormEntry(flow.requestContent, 'apid')
            results.append(Result.Result(flow, type_string, info))

            type_string = 'System Info: Hulu Device ID'
            info = findFormEntry(flow.requestContent, 'devid')
            results.append(Result.Result(flow, type_string, info))

            type_string = 'System Info: Brand'
            info = findFormEntry(flow.requestContent, 'manuf')
            results.append(Result.Result(flow, type_string, info))

            type_string = 'System Info: Model'
            info = findFormEntry(flow.requestContent, 'devmodel')
            results.append(Result.Result(flow, type_string, info))
    return


def analyzePostRequestDefault(flow, results):
    url = flow.get_url()
    if (False == checkFlowResults('IP Address', results)):
        info = flow.get_address()
        type_string = 'IP Address'
        results.append(Result.Result(flow, type_string, info))

    if (url == 'https://android.clients.google.com/c2dm/register3'):
        flow.source = flow.requestHeaders['app'] + ' GCM Login'
        type_string = 'System Info: Device ID'
        info = flow.requestContent
        info = info[info.find('device:') + 7:]
        info = info[:info.find('\n')]
        info = info.strip()
        results.append(Result.Result(flow, type_string, info))

        type_string = 'Token'
        info = flow.responseContent
        info = info[info.find('token=') + 6:]
        info = info.strip()
        results.append(Result.Result(flow, type_string, info))

        type_string = 'Certificate'
        info = findFormEntry(flow.requestContent, 'cert')
        results.append(Result.Result(flow, type_string, info))

    elif (url.find('appsflyer.com/api') > -1):
        content = flow.requestContent
        if (url.find('https://t.appsflyer.com/api') == 0):
            flow.source = flow.url[flow.url.find('app_id=') + 7:]
            flow.source = 'AppsFlyer ' + flow.source

        if (url.find('https://register.appsflyer.com/api') == 0):
            flow.source = content[content.find('"app_name":') + 13:]
            flow.source = flow.source[:flow.source.find('"')] + ' AppsFlyer'

        if (url.find('https://events.appsflyer.com/api') == 0):
            flow.source = flow.url[flow.url.find('app_id=') + 7:]
            if (flow.source.find('&') > -1):
                flow.source = flow.source[:flow.source.find('&')]
            flow.source = flow.source + ' AppsFlyer'

        type_string = 'Ad ID'
        info = content[content.find('"advertiserId":') + 17:]
        info = info[:info.find('"')]
        results.append(Result.Result(flow, type_string, info))

        if (flow.requestContent.find('"android_id":') > -1):
            type_string = 'Android ID'
            info = content[content.find('"android_id":') + 15:]
            info = info[:info.find('"')]
            results.append(Result.Result(flow, type_string, info))

        type_string = 'AppsFlyer Key'
        info = content[content.find('"appsflyerKey":') + 17:]
        info = info[:info.find('"')]
        results.append(Result.Result(flow, type_string, info))

        if (flow.requestContent.find('"counter":') > -1):
            type_string = 'User Info: Opened App Count'
            info = content[content.find('"counter":') + 12:]
            info = info[:info.find('"')]
            results.append(Result.Result(flow, type_string, info))

        if (flow.requestContent.find('"batteryLevel":') > -1):
            type_string = 'System Info: Battery Level'
            info = content[content.find('"batteryLevel":') + 17:]
            info = info[:info.find('"')] + '%'
            results.append(Result.Result(flow, type_string, info))

        type_string = 'System Info: Brand'
        info = content[content.find('"brand":') + 10:]
        info = info[:info.find('"')]
        results.append(Result.Result(flow, type_string, info))

        type_string = 'System Info: Build'
        info = content[content.find('"build_display_id":') + 21:]
        info = info[:info.find('"')]
        results.append(Result.Result(flow, type_string, info))

        if (flow.requestContent.find('x_px') > -1):
            type_string = 'System Info: Screen Size'
            width = content[content.find('"x_px":') + 9:]
            width = width[:width.find('"')]
            height = content[content.find('"y_px":') + 9:]
            height = height[:height.find('"')]
            info = width + ' x ' + height
            results.append(Result.Result(flow, type_string, info))

        if (flow.requestContent.find('sensors') > -1):
            type_string = 'System Info: Sensor Data'
            info = findJSONListNonSpaced(flow.requestContent, 'sensors')
            results.append(Result.Result(flow, type_string, info))

        if (flow.requestContent.find('"af_gcm_token":') > -1):
            type_string = 'AppFlyer GCM Token'
            info = content[content.find('"af_gcm_token":') + 17:]
            info = info[:info.find('"')]
            results.append(Result.Result(flow, type_string, info))

        type_string = 'System Info: App Version'
        info = content[content.find('"app_version_name":') + 21:]
        info = info[:info.find('"')]
        results.append(Result.Result(flow, type_string, info))

        type_string = 'System Info: App Install Date'
        info = content[content.find('"installDate":') + 16:]
        info = info[:info.find('"')]
        results.append(Result.Result(flow, type_string, info))

        if (flow.requestContent.find('"launch_counter":') > -1):
            type_string = 'User Info: App Launch Count'
            info = content[content.find('"launch_counter":') + 19:]
            info = info[:info.find('"')]
            results.append(Result.Result(flow, type_string, info))

        type_string = 'System Info: Model'
        brand = content[content.find('"brand":') + 10:]
        brand = brand[:brand.find('"')]
        model = content[content.find('"model":') + 10:]
        model = model[:model.find('"')]
        info = brand + ' ' + model
        results.append(Result.Result(flow, type_string, info))

        type_string = 'System Info: Network Connection'
        info = content[content.find('"network":') + 12:]
        info = info[:info.find('"')]
        results.append(Result.Result(flow, type_string, info))

        type_string = 'System Info: AppsFlyer UID'
        info = content[content.find('"uid":') + 8:]
        info = info[:info.find('"')]
        results.append(Result.Result(flow, type_string, info))

    elif (url == 'https://api.branch.io/v1/close'):
        flow.source = 'Branch.io'
        type_string = 'User Action: Closed App'
        branchkey = flow.requestContent[flow.requestContent.find('"branch_key":') + 15:]
        branchkey = branchkey[:branchkey.find('"')]
        sessionkey = flow.requestContent[flow.requestContent.find('"session_id":') + 15:]
        sessionkey = sessionkey[:sessionkey.find('"')]
        info = 'Closed App with Branch Key ' + branchkey + ' and session ID ' + sessionkey
        results.append(Result.Result(flow, type_string, info))

    elif (url.find('https://app.adjust.com') == 0):
        flow.source = 'adjust.com ' + findFormEntry(flow.requestContent, 'package_name')

        type_string = 'Ad ID'
        info = findFormEntry(flow.requestContent, 'gps_adid')
        results.append(Result.Result(flow, type_string, info))

        if (flow.requestContent.find('installed_at:') > -1):
            type_string = 'User Action: App Installation Time'
            info = findFormEntry(flow.requestContent, 'installed_at')
            results.append(Result.Result(flow, type_string, info))

        if (flow.requestContent.find('created_at:') > -1):
            type_string = 'Event Time'
            info = findFormEntry(flow.requestContent, 'created_at')
            results.append(Result.Result(flow, type_string, info))

        type_string = 'adjust.com Token: ' + findFormEntry(flow.requestContent, 'package_name')
        info = findFormEntry(flow.requestContent, 'app_token')
        results.append(Result.Result(flow, type_string, info))

        type_string = 'System Info: Brand'
        info = findFormEntry(flow.requestContent, 'device_manufacturer')
        results.append(Result.Result(flow, type_string, info))

        type_string = 'System Info: Model'
        info = findFormEntry(flow.requestContent, 'device_name')
        results.append(Result.Result(flow, type_string, info))

        type_string = 'System Info: Build'
        info = findFormEntry(flow.requestContent, 'os_build')
        results.append(Result.Result(flow, type_string, info))

        if (flow.requestContent.find('updated_at:') > -1):
            type_string = 'User Action: App Update Time'
            info = findFormEntry(flow.requestContent, 'updated_at')
            results.append(Result.Result(flow, type_string, info))

        if (flow.requestContent.find('click_time:') > -1):
            type_string = 'User Action: Click Time'
            info = findFormEntry(flow.requestContent, 'click_time')
            results.append(Result.Result(flow, type_string, info))

        type_string = 'System Info: Android UUID'
        info = findFormEntry(flow.requestContent, 'android_uuid')
        results.append(Result.Result(flow, type_string, info))

        type_string = 'System Info: Session Count'
        info = findFormEntry(flow.requestContent, 'session_count')
        results.append(Result.Result(flow, type_string, info))

        if (flow.requestContent.find('event_token:') > -1):
            type_string = 'adjust.com Event Token'
            info = findFormEntry(flow.requestContent, 'event_token')
            results.append(Result.Result(flow, type_string, info))

        if (flow.responseContent.find('"adid":') > -1):
            type_string = 'User Info: adjust.com Ad ID'
            info = flow.responseContent[flow.responseContent.find('"adid": "') + 9:]
            info = info[:info.find('"')]
            results.append(Result.Result(flow, type_string, info))

        if (flow.requestContent.find('callback_params') > -1):
            if (findFormEntry(flow.requestContent, 'package_name') == 'com.spotify.music'):
                callback = findFormEntry(flow.requestContent, 'callback_params')
                type_string = 'Spotify ID'
                info = callback[callback.find('"spotify_id":') + 14:]
                info = info[:info.find('"')]
                results.append(Result.Result(flow, type_string, info))

                if (callback.find('"session_id"') > -1):
                    type_string = 'Spotify Session ID'
                    info = callback[callback.find('"session_id":') + 14:]
                    info = info[:info.find('"')]
                    results.append(Result.Result(flow, type_string, info))

                if (callback.find('screen:') > -1):
                    type_string = 'User Action: Viewed Screen'
                    info = callback[callback.find('screen:') + 7:]
                    if (info.find(',') == -1):
                        info = info[:info.find('"')]
                    else:
                        if (info.find(',') < info.find('"')):
                            info = info[:info.find(',')]
                        else:
                            info = info[:info.find('"')]
                    results.append(Result.Result(flow, type_string, info))

                if (callback.find('clicked:') > -1):
                    type_string = 'User Action: Clicked'
                    info = callback[callback.find('clicked:') + 8:]
                    if (info.find(',') == -1):
                        info = info[:info.find('"')]
                    else:
                        if (info.find(',') < info.find('"')):
                            info = info[:info.find(',')]
                        else:
                            info = info[:info.find('"')]
                    results.append(Result.Result(flow, type_string, info))

                if (callback.find('input_field:') > -1):
                    type_string = 'User Action: Input Field'
                    info = callback[callback.find('input_field:') + 12:]
                    if (info.find(',') == -1):
                        info = info[:info.find('"')]
                    else:
                        if (info.find(',') < info.find('"')):
                            info = info[:info.find(',')]
                        else:
                            info = info[:info.find('"')]
                    results.append(Result.Result(flow, type_string, info))

                if (callback.find('event:') > -1):
                    type_string = 'Spotify Event'
                    info = callback[callback.find('event:') + 6:]
                    if (info.find(',') == -1):
                        info = info[:info.find('"')]
                    else:
                        if (info.find(',') < info.find('"')):
                            info = info[:info.find(',')]
                        else:
                            info = info[:info.find('"')]
                    results.append(Result.Result(flow, type_string, info))

        elif (url.find('sdk_click') > -1):
            if (findFormEntry(flow.requestContent, 'package_name') == 'com.spotify.music'):
                type_string = 'User Action: Click'
                info = findFormEntry(flow.requestContent, 'deeplink')
                results.append(Result.Result(flow, type_string, info))

    elif (url.find('https://vela.iad-01.braze.com') == 0):
        flow.source = 'Braze'

        type_string = 'Braze API Key'
        info = flow.requestContent[flow.requestContent.find('"api_key":') + 12:]
        info = info[:info.find('"')]
        results.append(Result.Result(flow, type_string, info))

        type_string = 'System Info: Braze ID'
        info = flow.requestContent[flow.requestContent.find('"device_id":') + 14:]
        info = info[:info.find('"')]
        results.append(Result.Result(flow, type_string, info))

        if (flow.requestContent.find('"push_token":') > -1):
            type_string = 'System Info: Braze Push Token'
            info = flow.requestContent[flow.requestContent.find('"push_token":') + 15:]
            info = info[:info.find('"')]
            results.append(Result.Result(flow, type_string, info))

        if (flow.requestContent.find('"model":') > -1):
            type_string = 'System Info: Model'
            info = flow.requestContent[flow.requestContent.find('"model":') + 10:]
            info = info[:info.find('"')]
            results.append(Result.Result(flow, type_string, info))

        if (flow.requestContent.find('"resolution":') > -1):
            type_string = 'System Info: Resolution'
            info = flow.requestContent[flow.requestContent.find('"resolution":') + 15:]
            info = info[:info.find('"')]
            results.append(Result.Result(flow, type_string, info))

        if (flow.requestContent.find('"session_id":') > -1):
            type_string = 'Braze Session ID'
            info = flow.requestContent[flow.requestContent.find('"session_id":') + 15:]
            info = info[:info.find('"')]
            results.append(Result.Result(flow, type_string, info))
    return


def analyzeHeadRequestDefault(flow, results):
    if (checkFlowResults('IP Address', results) == False):
        info = flow.address
        type_string = 'IP Address'
        results.append(Result.Result(flow.source, flow.destination, flow.source, type_string, info, flow.all))
    return

def analyzePutRequestDefault(flow, results):
    if (checkFlowResults('IP Address', results) == False):
        info = flow.get_address()
        type_string = 'IP Address'
        results.append(Result.Result(flow, type_string, info))
    return

def analyzeDeleteRequestDefault(flow, results):
    return None


def checkRequestHeadersDefault(flow, headers, results):
    if ('User-Agent' in headers.keys() and checkFlowResults('System Info: User-Agent', results) == False):
        info = headers['User-Agent']
        type_string = 'System Info: User-Agent'
        results.append(Result.Result(flow, type_string, info))
    if ('Cookie' in headers.keys() and checkFlowResults('System Info: Cookie', results) == False):
        info = headers['Cookie']
        type_string = 'System Info: Cookie'
        results.append(Result.Result(flow, type_string, info))
    if ('x-dfe-device-id' in headers.keys() and checkFlowResults('System Info: Device ID', results) == False):
        info = headers['x-dfe-device-id']
        type_string = 'System Info: Device ID'
        results.append(Result.Result(flow, type_string, info))
    if ('x-dfe-device-config-token' in headers.keys() and checkFlowResults('System Info: Config Token',
                                                                           results) == False):
        info = headers['x-dfe-device-config-token']
        type_string = 'System Info: Config Token'
        results.append(Result.Result(flow, type_string, info))
    if ('x-ad-id' in headers.keys()):
        info = headers['x-ad-id']
        type_string = 'User Info: Ad ID'
        results.append(Result.Result(flow, type_string, info))
    if ('Authorization' in headers.keys()):
        info = headers['Authorization']
        type_string = 'Authorization'
        results.append(Result.Result(flow, type_string, info))
    if ('x-device-boot-count' in headers.keys()):
        info = headers['x-device-boot-count']
        type_string = 'System Info: Boot Count'
        results.append(Result.Result(flow, type_string, info))
    if ('x-device-id' in headers.keys()):
        info = headers['x-device-id']
        type_string = 'System Info: Device ID'
        results.append(Result.Result(flow, type_string, info))
    return


def checkResponseHeadersDefault(flow, headers, results):
    try:
        if ('Set-Cookie' in headers.keys()):
            info = headers['Set-Cookie']
            type_string = 'System Info: Cookie'
            results.append(Result.Result(flow, type_string, info))
        if ('Set-Cookie-1' in headers.keys()):
            info = headers['Set-Cookie-1']
            type_string = 'System Info: Cookie'
            results.append(Result.Result(flow, type_string, info))
        if ('Set-Cookie-2' in headers.keys()):
            info = headers['Set-Cookie-2']
            type_string = 'System Info: Cookie'
            results.append(Result.Result(flow, type_string, info))
        if ('Content-Type' in headers.keys() and headers['Content-Type'][:5] == 'image' and flow.url.find(
                'app-measurement.com') < 0):
            if (flow.source != 'Google Analytics'):
                if (len(flow.source) > 0):
                    flow.source = flow.source + ' Image Download'
                else:
                    flow.source = 'Image Download'
        elif ('Content-Type' in headers.keys() and headers['Content-Type'][:4] == 'font'):
            if (len(flow.source) > 0):
                flow.source = flow.source + ' Font Download'
            else:
                flow.source = 'Font Download'
        return
    # noinspection PyBroadException
    except:
        return


def checkFlowResults(result_type, results):
    for result in results:
        if (result.type == result_type):
            return True
    return False


def syncSource(flow, results):
    for item in results:
        item.source = flow.get_source()
        item.sync_source_log()
    return


def cleanEncoding(input_string):
    output = ''
    while (len(input_string) >= 4):
        output = output + input_string[:input_string.find('\\x')]
        input_string = input_string[input_string.find('\\x') + 4:]
        if input_string[:1] == '_':
            input_string = input_string[2:]
    return output


def fixUrlEncoding(input_string):
    output = ''
    while (len(input_string) >= 3):
        output = output + input_string[:input_string.find('%')]
        input_string = input_string[input_string.find('%'):]
        temp = input_string[:3]
        input_string = input_string[3:]
        if (temp == '%3A'):
            temp = ':'
        elif (temp == '%20'):
            temp = ' '
        output = output + temp
    output = output + input_string
    return output


def findFormEntry(content, entry):
    line = content[content.find(entry + ':'):]
    if (line.find('\n') > -1):
        line = line[:line.find('\n')]
    answer = line[len(entry) + 1:].strip()
    return answer


def findJSONSection(content, section):
    part = content[content.find('"' + section + '": {'):]
    temp = part
    part = part[:part.find('\n') + 1]
    count = 1
    while count > 0 and (temp[temp.find('\n') + 1:].strip() != '(cut off)'):
        temp = temp[temp.find('\n') + 1:]
        line = temp[:temp.find('\n') + 1]
        part = part + line
        line = line.strip()
        if (line[:1] == '{'):
            count = count + 1
        elif (line[:1] == '}'):
            count = count - 1
    return part


def findJSONList(content, list_name):
    part = content[content.find('"' + list_name + '": ['):]
    temp = part
    part = part[:part.find('\n') + 1]
    count = 1
    while count > 0:
        temp = temp[temp.find('\n') + 1:]
        line = temp[:temp.find('\n') + 1]
        part = part + line
        line = line.strip()
        if (line[:1] == '['):
            count = count + 1
        elif (line[:1] == ']'):
            count = count - 1
    part = part[part.find('\n') + 1:]
    items = []
    temp = ''
    count = 0
    for line in part.split('\n'):
        if (line.strip()[:1] == '{' or line.strip()[len(line) - 2:] == '{'):
            if (count == 0 and len(temp) > 0):
                items.append(temp)
                temp = line
            else:
                temp = temp + line + '\n'
                count = count + 1
        elif (line.strip()[:1] == '}'):
            temp = temp + line + '\n'
            count = count - 1
        else:
            temp = temp + line + '\n'
    items.append(temp)
    return items


def findJSONListNonSpaced(content, list_name):
    part = content[content.find('"' + list_name + '":'):]
    part = part[part.find('['):]
    count = 1
    index = 1
    while count > 0:
        if (part[index:index + 9] == '(cut off)'):
            count = 0
        else:
            if (part[index:index + 1] == '['):
                count = count + 1
            elif (part[index:index + 1] == ']'):
                count = count - 1
            index = index + 1
    part = part[:index]
    return part


def findJSONItem(content, item_name):
    item = content[content.find(item_name):]
    comma = item[:item.find(',')]
    bracket = item[:item.find('}')]
    if (item.find(',') > -1 and item.find('}') > -1):
        if (len(comma) < len(bracket)):
            item = comma
        else:
            item = bracket
    elif (item.find(',') > -1):
        item = comma
    elif (item.find('}') > -1):
        item = bracket
    item = item[item.find(':') + 1:].strip()
    if (item[:1] == '"' and item[len(item) - 1:len(item)] == '"'):
        item = item[1:len(item) - 1]
    return item


def findJSONGroup(content, group_name):
    bracket_index = len(group_name) + 2
    group = content[content.find(group_name):]
    while bracket_index > (len(group_name) + 1):
        group = group[len(group_name) + 1:]
        group = group[group.find(group_name):]
        bracket_index = group.find('{')
    group = group[bracket_index + 1:]
    count = 1
    index = 1
    while count > 0:
        if group[index:index + 9] == '(cut off)':
            count = 0
        else:
            if group[index:index + 1] == '{':
                count = count + 1
            elif group[index:index + 1] == '}':
                count = count - 1
            index = index + 1
    group = group[:index + bracket_index]
    return group
