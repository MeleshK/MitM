import gc
import pandas as pd
import time
import os
import whois
import glob
import matplotlib
from random import randrange

filenames = []
ignore_list = ['knight22.com', '10.0.0.31', '10.0.0.2', 'local']


def func_get_tld_info(list_of_tld):
    # either create or open a dataframe for the tld data
    if os.path.isfile(cwd + "/Output/Stage2/Host_Info/TLD_Info.csv"):
        tld_data = pd.read_csv(cwd + "/Output/Stage2/Host_Info/TLD_Info.csv")
    else:
        tld_data = pd.DataFrame(columns=["TLD", "Org", "Country"])

    # create list of already searched TLDs
    tld_data_list = tld_data['TLD'].unique()
    # loop through TLDs in the results file, nothing to do if extant, otherwise look it up
    for tld in list_of_tld:
        if tld in tld_data_list:
            print("TLD already looked up - " + tld)
        else:
            print("Looking up TLD - " + tld)
            # whois does not support the .google TLD domain
            # Valid TLDs: .ac_uk .am .amsterdam .ar .at .au .bank .be .biz .br .by .ca .cc .cl .club .cn .co
            # .co_il  .co_jp .com .com_au .com_tr .cr .cz .de .download .edu .education .eu .fi .fm .fr .frl
            # .game .global_  .hk .id_ .ie .im .in_ .info .ink .io .ir .is_ .it .jp .kr .kz .link .lt .lv .me
            # .mobi .mu .mx .name .net .ninja .nl .nu .nyc .nz .online .org .pe .pharmacy .pl .press .pro .pt
            # .pub .pw .rest .ru .ru_rf .rw .sale .se .security .sh .site .space .store .tech .tel .theatre
            # .tickets .trade .tv .ua .uk .us .uz .video .website .wiki .work .xyz .za
            if tld == 'dns.google':
                tld_data = tld_data.append({'TLD': tld, 'Org': "Google LLC", 'Country': 'US'},
                                           ignore_index=True)
            else:
                try:
                    domain = whois.query(tld)
                    tld_data = tld_data.append(
                        {'TLD': tld, 'Org': domain.registrant, 'Country': domain.registrant_country},
                        ignore_index=True)
                    time.sleep(randrange(1, 3))  # need a slight delay between requests for WHOIS info
                except whois.exceptions.WhoisCommandFailed:
                    print("Error with Whois lookup")
                    exit(-1)

    tld_data.to_csv(cwd + "/Output/Stage2/Host_Info/TLD_Info.csv")
    del tld_data_list
    gc.collect()
    return tld_data


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    cwd = os.getcwd()
    print(cwd)
    filenames = sorted(glob.glob(cwd + '/Output/Stage1/*.csv'))
    for file in filenames:
        # Extract filename for saving files
        base = os.path.basename(file)
        filename = os.path.splitext(base)[0]
        del base
        gc.collect()

        if os.path.isfile(cwd + "/Output/Stage2/Host_Data/" + filename + '.csv'):
            print("Already processed - " + file)
        else:
            print("\nProcessing " + file)
            mitm_data = pd.read_csv(file)
            # Using pandas function to replace nan values
            mitm_data = mitm_data.fillna("")
            # filter out local traffic
            for filter_string in ignore_list:
                mitm_data = mitm_data[mitm_data.TLD != filter_string]

            # app_list = mitm_data['Application'].unique()
            # user_agent_list = mitm_data['UserAgent'].unique()
            tld_list = mitm_data['TLD'].unique()
            # Save the host data to a file, so can free the memory
            mitm_data.to_csv(cwd + "/Output/Stage2/Host_Data/" + filename + '.csv')
            del mitm_data
            gc.collect()

            tld_info = func_get_tld_info(tld_list)

            host_info_data = pd.read_csv(file)
            host_info_data = host_info_data.drop(columns=['URL', 'Info', 'Destination', 'Source', 'Host'])

            # create two empty columns for Organisation and Country Info
            host_info_data['Org'] = ""
            host_info_data['Country'] = ""

            # loop through whois info setting country and organisation data
            for ind in tld_info.index:
                host_info_data.loc[host_info_data.TLD == tld_info['TLD'][ind], "Org"] = tld_info['Org'][ind]
                host_info_data.loc[host_info_data.TLD == tld_info['TLD'][ind], "Country"] = tld_info['Country'][ind]
            # Save the host data to a file
            host_info_data.to_csv(cwd + "/Output/Stage2/Host_Data/" + filename + '.csv')
            # Generate and save User Agent pie chart
            title_string = 'TLD accessed - ' + filename
            graph_count = host_info_data.drop(columns=['Application', 'TLD', 'Country']).groupby('UserAgent').count()
            # Generate and  save User Agent graph
            pie = graph_count.plot(kind="pie", title=title_string, figsize=(15, 15), legend=False, use_index=False, subplots=True)
            fig1 = pie[0].get_figure()
            fig1.savefig(cwd + "/Output/Stage2/Images/" + filename + "_user_agent_pie_graph.png", bbox_inches='tight', dpi=1200)

            # Generate and save TLD pie chart
            title_string = 'TLD accessed - ' + filename
            graph_count = host_info_data.drop(columns=['Application', 'Country']).groupby('TLD').count()
            pie = graph_count.plot(kind="pie", title=title_string, figsize=(15, 15), legend=False, use_index=False, subplots=True)
            fig2 = pie[0].get_figure()
            fig2.savefig(cwd + "/Output/Stage2/Images/" + filename + "_TLD_pie_graph.png", bbox_inches='tight', dpi=1200)

            # Generate and save organisation pie chart
            title_string = 'Company ownership of TLD accessed - ' + filename
            graph_count = host_info_data.drop(columns=['Application', 'Country', 'UserAgent']).groupby('Org').count()
            pie = graph_count.plot(kind="pie", title=title_string, figsize=(15, 15), legend=False, use_index=False, subplots=True)
            fig3 = pie[0].get_figure()
            fig3.savefig(cwd + "/Output/Stage2/Images/" + filename + "_org_pie_graph.png", bbox_inches='tight', dpi=1200)
