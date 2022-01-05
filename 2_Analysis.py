import pandas as pd
import time
import os
import whois
import glob
import matplotlib
from random import randrange

filenames = []
ignore_list = ['knight22.com', '10.0.0.31']


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    cwd = os.getcwd()
    filenames = glob.glob(cwd + '/Output/Stage1/*.csv')
    print(filenames)
    for file in filenames:
        # Extract filename for saving files
        base = os.path.basename(file)
        filename = os.path.splitext(base)[0]

        if os.path.isfile(cwd + "/Output/Stage2/Host_Data/" + filename + '.csv'):
            print("Already processed - " + file)
        else:
            print("\nLoading " + file)
            mitm_data = pd.read_csv(file)
            # Using pandas function to replace nan values
            mitm_data = mitm_data.fillna("")
            # filter out local traffic
            for filter_string in ignore_list:
                mitm_data = mitm_data[mitm_data.TLD != filter_string]

            tld_list = mitm_data['TLD'].unique()
            # retrieve org information for all TLD
            tld_data = pd.DataFrame(columns=["TLD", "Org", "Country"])
            for tld in tld_list:
                print("Whois lookup:" + tld)
                w = whois.whois(tld)
                if w.org == "":
                    exit(5)
                tld_data = tld_data.append({'TLD': tld, 'Org': w.org, 'Country': w.country}, ignore_index=True)

                time.sleep(randrange(5))  # need a slight delay between requests for WHOIS info
            tld_data.to_csv(cwd + "/Output/Stage2/Host_Info/" + filename + '.csv')
            host_info_data = mitm_data.drop(columns=['URL', 'Info', 'Destination', 'Source', 'Host'])

            # create two empty columns for Organisation and Country Info
            host_info_data['Org'] = ""
            host_info_data['Country'] = ""

            # loop through whois info setting country and organisation data
            for ind in tld_data.index:
                host_info_data.loc[host_info_data.TLD == tld_data['TLD'][ind], "Org"] = tld_data['Org'][ind]
                host_info_data.loc[host_info_data.TLD == tld_data['TLD'][ind], "Country"] = tld_data['Country'][ind]

            host_info_data.to_csv(cwd + "/Host_Data/" + filename + '.csv')
            # Generate and save application graph
            fig = host_info_data.drop(columns=['Org', 'Country']).groupby('Application').count().plot(kind="bar", figsize=(20, 20)).get_figure()
            # save application graph
            fig.savefig(cwd + "/Output/Stage2/Images/" + filename + "_application_graph.png", bbox_inches='tight', dpi=600)
            # Generate and save TLD graph
            fig2 = host_info_data.drop(columns=['Application', 'Country']).groupby('TLD').count().plot(kind="bar", figsize=(20, 20)).get_figure()
            fig2.savefig(cwd + "/Output/Stage2/Images/" + filename + "_tld_graph.png", bbox_inches='tight', dpi=600)
            # Generate and save Organisation graph
            fig3 = host_info_data.drop(columns=['Application', 'Country']).groupby('Org').count().plot(kind="bar", figsize=(20, 20)).get_figure()
            fig3.savefig(cwd + "/Output/Stage2/Images/" + filename + "_org_graph.png", bbox_inches='tight', dpi=600)

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
