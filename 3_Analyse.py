import constants
import pandas as pd
import time
import os
import whois
import glob
import matplotlib
from random import randrange

filenames = []


def func_get_tld_info(l_filename, list_of_tld):
    tld_data = pd.DataFrame(columns=["TLD", "Organization", "Country"])

    for tld in list_of_tld:
        print("Looking up TLD - " + tld)
        # whois does not support the .google TLD domain
        # Valid TLDs: .ac_uk .am .amsterdam .ar .at .au .bank .be .biz .br .by .ca .cc .cl .club .cn .co
        # .co_il  .co_jp .com .com_au .com_tr .cr .cz .de .download .edu .education .eu .fi .fm .fr .frl
        # .game .global_  .hk .id_ .ie .im .in_ .info .ink .io .ir .is_ .it .jp .kr .kz .link .lt .lv .me
        # .mobi .mu .mx .name .net .ninja .nl .nu .nyc .nz .online .org .pe .pharmacy .pl .press .pro .pt
        # .pub .pw .rest .ru .ru_rf .rw .sale .se .security .sh .site .space .store .tech .tel .theatre
        # .tickets .trade .tv .ua .uk .us .uz .video .website .wiki .work .xyz .za
        if tld == 'dns.google':
            tld_data = tld_data.append({'TLD': tld, 'Organization': "Google LLC", 'Country': 'US'},
                                       ignore_index=True)
        else:
            i_count = 0
            while i_count < constants.WHOIS_LOOKUP_COUNT:
                t_sec = randrange(constants.WHOIS_LOOKUP_WAIT_MIN, constants.WHOIS_LOOKUP_WAIT_MAX)
                try:
                    domain = whois.query(tld)
                    tld_data = tld_data.append(
                        {'TLD': tld, 'Organization': domain.registrant, 'Country': domain.registrant_country},
                        ignore_index=True)
                    i_count = constants.WHOIS_LOOKUP_COUNT
                except whois.UnknownTld:
                    print("Unknown TLD")
                    exit(-1)
                time.sleep(t_sec)  # need a slight delay between requests for WHOIS info
                i_count += 1
    tld_data.to_csv(l_filename + '.csv', index=False)
    return tld_data


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    cwd = os.getcwd()
    filenames = sorted(glob.glob(cwd + '/Output/Stage1/*.csv'))
    for file in filenames:
        # Extract filename for saving files
        base = os.path.basename(file)
        filename = os.path.splitext(base)[0]

        print("\nProcessing " + file)
        mitm_data = pd.read_csv(file)
        # Using pandas function to replace nan values
        mitm_data = mitm_data.fillna("")
        mitm_data.drop(columns=['Host'])
        # filter out local traffic
        for filter_string in constants.IGNORE_LIST:
            mitm_data = mitm_data[mitm_data.TLD != filter_string]

        path = os.path.join(cwd + "/Output/Stage2/", filename)
        # make a folder for the results
        try:
            os.mkdir(path)
            os.mkdir(path+"/Images")
        except OSError as error:
            print(error)

        # Save summary file
        with open(path + "/" + filename + '_Summary.txt', 'w') as f:
            if constants.LOOKUP_TLD_INFO:
                # create two empty columns for Organisation and Country Info
                mitm_data['Organization'] = ""
                mitm_data['Country'] = ""
            f.write(filename + ' - Summary\n')
            for column in mitm_data.columns:
                print("Processing " + column)
                f.write("\nUnique " + column)
                unique_values = mitm_data[column].unique()
                unique_values_counts = mitm_data[column].value_counts()

#                column_df = pd.DataFrame(list(zip(unique_values, unique_values_counts)), columns=[column, 'Frequency'])
                column_df = pd.DataFrame(unique_values_counts, index=unique_values)
                column_df.to_csv(path + "/" + filename + "_" + column + ".csv")

                if ("TLD" == column) & constants.LOOKUP_TLD_INFO:
                    tld_info = func_get_tld_info(path, unique_values)

                    # loop through whois info setting country and organisation data
                    for ind in tld_info.index:
                        mitm_data.loc[mitm_data.TLD == tld_info['TLD'][ind], "Organization"] = tld_info['Organization'][ind]
                        mitm_data.loc[mitm_data.TLD == tld_info['TLD'][ind], "Country"] = tld_info['Country'][ind]
                iterator = 0
                while iterator < len(unique_values):
                    f.write("\n")
                    f.write(str(unique_values[iterator]))
                    f.write("\t")
                    f.write(str(unique_values_counts[iterator]))
                    iterator += 1
                f.write("\n")
                if len(unique_values) > 1:
                    if column != "URL":
                        if column != "UserAgent":
                            print("Preparing " + column + " bar graph")
                            title_string = str(filename.replace("_", " ") + " - " + column)
                            # bar graph
                            fig = column_df.plot(kind="bar", title=title_string, figsize=(15, 15), legend=False,
                                                 xlabel=column, ylabel="Frequency").get_figure()
                            fig.savefig(path + "/Images/" + filename + "_" + column + "_bar_graph.png",
                                        bbox_inches='tight', dpi=600)
                            matplotlib.pyplot.close(fig)

                            print("Preparing " + column + " pie graph")
                            # Pie graph
                            pie = column_df.plot.pie(subplots=True, title=title_string, figsize=(15, 15), ylabel='',
                                                     legend=False)
                            fig = pie[0].get_figure()
                            fig.savefig(path + "/Images/" + filename + "_" + column + "_pie_graph.png",
                                        bbox_inches='tight', dpi=600)
                            # Need to close the figure otherwise it will use up memory for no benefit.
                            matplotlib.pyplot.close(fig)
            f.close()
