# Function to calculate signal strength (placeholder for Telecom)

import math


def el1_tx_power_cal(numbers):

    logs = []
    logs.append("----------------------------------")
     # Log message for Box D
     #{'channel_type': '1', 'Preamble_init_power-id': '3', 'preamble_transmission_counter-id': '4', 'power_ramping_step-id': '4', 'Poth_loss-id-1': '4', 'Pcmax-id-1': None}
     #{'channel_type': '2', '0_nom_PUCCH-id': '4', 'P0_ue_PUCCH-id': '4', 'pl-id': '4', 'PucchFrm_h': '4', 'delta_f-id': '4', 'g_i-id': '4', 'Pcmax-id-2': None}
     #{'channel_type': '3', 'log_m_pusch-id': '1', 'P0_nom_PUSCH-id': '1', 'P0_ue_PUSCH-id': '1', 'alpha-id': '1', 'pl-id-1': '1', 'delta-tf-id': '1', 'g_i-id-1': '1', 'Pcmax-id-3': '1'}
     #{'channel_type': '4', 'log_m_pusch-id-2': '1', 'Preamble_init_power-id-2': '11', 'delta_msg3-id': '1', 'pl-id-2': '1', 'f_0-id': '1'}
     #SRS Power cal :  {'channel_type': '5', 'P_SRS_Offset-id': '1', 'log-m-srs': '1', 'p0-num-pusch-id': '1', 'P0_UE_PUSCH-id': '1', 'alpha-id': '1', 'pl-id-3': '1', 'f(i)-id': '1', 'pcmax-id-4': None}
     #{'channel_type': '6', 'sfn-id': '1', 'np-id': '1', 'ns-id': '1', 'n_offset_cqi-id': '1'}
    def ALPHA_api(alpha):
                if alpha == 0:
                    return 0
                elif alpha == 1:
                    return 0.4
                elif alpha == 2:
                    return 0.4
                elif alpha == 3:
                    return 0.6
                elif alpha == 4:
                    return 0.7
                elif alpha == 5:
                    return 0.8
                elif alpha == 6:
                    return 0.9
                elif alpha == 7:
                    return 1
    try:
        results = None
        if numbers['channel_type'] == '1':

            Preamble_init_power = int(numbers['Preamble_init_power-id'])
            preamble_transmission_counter = int(numbers['preamble_transmission_counter-id'])
            power_ramping_step = int(numbers['power_ramping_step-id'])
            pl = int(numbers['Poth_loss-id-1'])
            pcmax = numbers['Pcmax-id-1']

            parch_cal_pwr = Preamble_init_power + (preamble_transmission_counter-1) * power_ramping_step + pl

            
            if pcmax != None: 
                results = f"PRACH power is : {parch_cal_pwr} \n Final pwr = min(pcmax,Prach power) = {min(int(pcmax),parch_cal_pwr)}"

            else:
                results = f"PRACH power is : {parch_cal_pwr}"

        elif numbers['channel_type'] == '2':
            
            p_zero_nom_pucch = int(numbers['0_nom_PUCCH-id'])
            p_ue_PUCCH_id = int(numbers['P0_ue_PUCCH-id'])
            PucchFrm_h = int(numbers['PucchFrm_h'])
            delta_f = int(numbers['delta_f-id'])
            g_i = int(numbers['g_i-id'])
            pl = int(numbers['pl-id'])
            pcmax = numbers['Pcmax-id-2']

            pucch_cal_pwr  = (p_zero_nom_pucch + p_ue_PUCCH_id) + pl + PucchFrm_h + delta_f + g_i

            
            if pcmax != None: 
                results = f"PUCCH power is : {pucch_cal_pwr} \n Final pwr = min(pcmax,Prach power) = {min(int(pcmax),pucch_cal_pwr)}"

            else:
                results = f"PUCCH power is : {pucch_cal_pwr}"
            

        elif numbers['channel_type'] == '3':


                
                
            log_m_pusch = int(numbers['log_m_pusch-id'])
            p0_num_pusch = int(numbers['P0_nom_PUSCH-id'])
            p0_ue_pusch = int(numbers['P0_ue_PUSCH-id'])
            alpha = int(numbers['alpha-id'])
            f_i = int(numbers['f_i-id-1'])
            delta_tf = int(numbers['delta-tf-id'])
            pl = int(numbers['pl-id-1'])
            pcmax = numbers['Pcmax-id-3']
            
            alpha_final  = ALPHA_api(alpha)

            pusch_cal_pwr = log_m_pusch + ( p0_num_pusch + p0_ue_pusch) + alpha_final * pl + delta_tf + f_i


            if pcmax != None: 
                results = f"PUSCH power is : {pusch_cal_pwr} \n Final pwr = min(pcmax, pusch power) = {min(int(pcmax),pusch_cal_pwr)}"

            else:
                results = f"PUSCH power is : {pusch_cal_pwr}"
            

        elif numbers['channel_type'] == '4':
    
            log_m_pusch = int(numbers['log_m_pusch-id-2'])
            Preamble_init_power = int(numbers['Preamble_init_power-id-2'])
            delta_msg3 = int(numbers['delta_msg3-id'])

            pl = int(numbers['pl-id-2'])
            f_0 = int(numbers['f_0-id'])

            msg3_tx_pwr = log_m_pusch + (Preamble_init_power + delta_msg3) + pl + f_0
            results = f"MSG3 TX Power : {msg3_tx_pwr}"


        elif numbers['channel_type'] == '5':
    

            logs.append("*** SRS Power Cal.. ***")
            srsBW = int(numbers['srsBW-id'])  # Ensure numbers is a valid dictionary
            log_m_srs = 10 * math.log10(srsBW)  # Use srsBW directly

            delta_mcs = int(numbers['delta_mcs_enabled-id'])
            srs_offset = int(numbers['srs_offset-id'])

            if delta_mcs == 0:
                P_SRS_Offset = -10.5 + (1.5*srs_offset)
                logs.append(f"=> P_Srs_Offset = -10.5 + (1.5 * {srs_offset}) => {P_SRS_Offset} ")
            elif delta_mcs == 1:
                P_SRS_Offset = -3 + (1*srs_offset)
                logs.append(f"=> P_Srs_Offset = -3 + (1 * {srs_offset}) => {P_SRS_Offset} ")
            

            p0_num_pusch= int(numbers['p0-num-pusch-id'])
            P0_UE_PUSCH = int(numbers['P0_UE_PUSCH-id'])

            alpha = int(numbers['alpha-id'])
            pl = int(numbers['pl-id-3'])
            f_i= int(numbers['f(i)-id'])
            pcmax= numbers['pcmax-id-4']


            final_alpha = ALPHA_api(alpha)
            logs.append(f"=>Final Alpha = alpha_api({alpha}) => {final_alpha}")

            srs_power = P_SRS_Offset + log_m_srs + (p0_num_pusch  + P0_UE_PUSCH) + final_alpha * pl + f_i
            logs.append(f"\n=>SRS_formula = P_SRS_Offset + log_m_srs + (p0_num_pusch  + P0_UE_PUSCH) + final_alpha * pl + f_i ")
            logs.append(f"\n===> {P_SRS_Offset} + {log_m_srs} + ({p0_num_pusch}  + {P0_UE_PUSCH}) + {final_alpha} * {pl} + {f_i} ")
            logs.append(f"\n======> Calc SRS power is : {srs_power}")




            if pcmax != None: 
                results = f"SRS power is : {srs_power} \n Final pwr = min(pcmax, pusch power) = {min(int(pcmax),srs_power)}"

            else:
                results = f"SRS power is : {srs_power}"


        elif numbers['channel_type'] == '6':
        
            sfn = int(numbers['sfn-id'])
            np = int(numbers['np-id'])
            ns = int(numbers['ns-id'])
            n_offset_cqi = int(numbers['n_offset_cqi-id'])


            pcsi = ( (10 * sfn) + (ns/2) - n_offset_cqi) % np

            results = f"Periodic CSI Occasion : {pcsi}"  

        
        logs.append(f"{results}") 
        
        return str(results), logs
    except ValueError as e:
        error_msg = "Invalid input. Please enter valid numbers (only int/float values)."
        logs.append(f"Error: {error_msg}")
        return f"Error: {error_msg}", logs


def calculate_two_db_total_power(numbers):
    """
    it will take input as two db's and return the total power. 

    """
    logs = []
    logs.append("----------------------------------")
     # Log message for Box D
    try:
        db1 = 10 ** (int(numbers[0])/10)
        db2 = 10 ** (int(numbers[1])/10)

        total = db1 + db2


        convert_db = 10 * math.log10(total)
        result = f"{convert_db} dB"
        logs.append(f"Total Power of Two db's ({numbers[0]},{numbers[1]})=> {result} ") 
        

        
        return str(result), logs
    except ValueError as e:
        error_msg = "Invalid input. Please enter valid numbers (only int/float values)."
        logs.append(f"Error: {error_msg}")
        return f"Error: {error_msg}", logs
    
def conv_te_sfn_to_ue_sfn(numbers):
    """
    It will take TE SFN no. to UE SFN number  

    """
    logs = []
    logs.append("------------------------")  # Log message for Box D
    try:
        TE_SFN = int(numbers[0])  # Power in dBm

        result = TE_SFN % 1024  # Example: 2 dBm loss per km
        logs.append(f"value mod 1024 : {result} ")  # Log message for Box D

        return str(result), logs
        
    except ValueError as e:
        error_msg = "Invalid input. Please enter valid numbers."
        logs.append(f"Error: {error_msg}")
        return f"Error: {error_msg}", logs


def earfcn_to_dl_freq(numbers):
    """
    Convert either DL or UL EARFCN to downlink and uplink frequencies (MHz), EARFCNs, band, and duplex mode based on 3GPP TS 36.101.
    Input: List containing a single EARFCN (integer), either DL or UL.
    Output: Tuple of (result string with newlines, logs list containing the result string and band table).
    """
    logs = []
    try:
        earfcn = int(numbers[0])
        LTE_FREQ_INV = 0xFFFF  # Invalid frequency marker
        LTE_EARFCN_INV = 0xFFFFFFFF  # Invalid EARFCN marker

        # LTE band data: (band, dl_freq_low, dl_freq_high, ul_freq_low, ul_freq_high, dl_earfcn_low, ul_earfcnl, band_num, duplex_mode)
        bands = [
            (0, LTE_FREQ_INV, LTE_FREQ_INV, LTE_FREQ_INV, LTE_FREQ_INV, LTE_EARFCN_INV, LTE_EARFCN_INV, 0, "N/A"),
            (1, 21100, 21700, 19200, 19800, 0, 18000, 1, "FDD"),
            (2, 19300, 19900, 18500, 19100, 600, 18600, 2, "FDD"),
            (3, 18050, 18800, 17100, 17850, 1200, 19200, 3, "FDD"),
            (4, 21100, 21550, 17100, 17550, 1950, 19950, 4, "FDD"),
            (5, 8690, 8940, 8240, 8490, 2400, 20400, 5, "FDD"),
            (7, 26200, 26900, 25000, 25700, 2750, 20750, 7, "FDD"),
            (8, 9250, 9600, 8800, 9150, 3450, 21450, 8, "FDD"),
            (9, 18449, 18799, 17499, 17849, 3800, 21800, 9, "FDD"),
            (10, 21100, 21700, 17100, 17700, 4150, 22150, 10, "FDD"),
            (11, 14759, 14959, 14279, 14479, 4750, 22750, 11, "FDD"),
            (12, 7290, 7460, 6990, 7160, 5010, 23010, 12, "FDD"),
            (13, 7460, 7560, 7770, 7870, 5180, 23180, 13, "FDD"),
            (14, 7580, 7680, 7880, 7980, 5280, 23280, 14, "FDD"),
            (17, 7340, 7460, 7040, 7160, 5730, 23730, 17, "FDD"),
            (18, 8600, 8750, 8150, 8300, 5850, 23850, 18, "FDD"),
            (19, 8750, 8900, 8300, 8450, 6000, 24000, 19, "FDD"),
            (20, 7910, 8210, 8320, 8620, 6150, 24150, 20, "FDD"),
            (21, 14959, 15109, 14479, 14629, 6450, 24450, 21, "FDD"),
            (22, 35100, 35900, 34100, 34900, 6600, 24600, 22, "FDD"),
            (24, 15250, 15590, 16265, 16605, 7700, 25700, 24, "FDD"),
            (25, 19300, 19950, 18500, 19150, 8040, 26040, 25, "FDD"),
            (26, 8590, 8940, 8140, 8490, 8690, 26690, 26, "FDD"),
            (27, 8520, 8690, 8070, 8240, 9040, 27040, 27, "FDD"),
            (28, 7580, 8030, 7030, 7480, 9210, 27210, 28, "FDD"),
            (29, 7170, 7280, LTE_FREQ_INV, LTE_FREQ_INV, 9660, LTE_EARFCN_INV, 29, "SDL"),
            (30, 23500, 23600, 23050, 23150, 9770, 27660, 30, "FDD"),
            (31, 4625, 4675, 4525, 4575, 9870, 27760, 31, "FDD"),
            (32, 14520, 14960, LTE_FREQ_INV, LTE_FREQ_INV, 9920, LTE_EARFCN_INV, 32, "SDL"),
            (33, 19000, 19200, 19000, 19200, 36000, 36000, 33, "TDD"),
            (34, 20100, 20250, 20100, 20250, 36200, 36200, 34, "TDD"),
            (35, 18500, 19100, 18500, 19100, 36350, 36350, 35, "TDD"),
            (36, 19300, 19900, 19300, 19900, 36950, 36950, 36, "TDD"),
            (37, 19100, 19300, 19100, 19300, 37550, 37550, 37, "TDD"),
            (38, 25700, 26200, 25700, 26200, 37750, 37750, 38, "TDD"),
            (39, 18800, 19200, 18800, 19200, 38250, 38250, 39, "TDD"),
            (40, 23000, 24000, 23000, 24000, 38650, 38650, 40, "TDD"),
            (41, 24960, 26900, 24960, 26900, 39650, 39650, 41, "TDD"),
            (42, 34000, 36000, 34000, 36000, 41590, 41590, 42, "TDD"),
            (43, 36000, 38000, 36000, 38000, 43590, 43590, 43, "TDD"),
            (44, 7030, 8030, 7030, 8030, 45590, 45590, 44, "TDD"),
            (45, 14470, 14670, 14470, 14670, 46590, 46590, 45, "TDD"),
            (46, 51500, 59250, 51500, 59250, 46790, 46790, 46, "TDD"),
            (47, 58550, 59250, 58550, 59250, 54540, 54540, 47, "TDD"),
            (48, 35500, 37000, 35500, 37000, 55240, 55240, 48, "TDD"),
            (49, 35500, 37000, 35500, 37000, 56740, 56740, 49, "TDD"),
            (50, 14320, 15170, 14320, 15170, 58240, 58240, 50, "TDD"),
            (51, 14270, 14320, 14270, 14320, 59090, 59090, 51, "TDD"),
            (52, 33000, 34000, 33000, 34000, 59140, 59140, 52, "TDD"),
            (53, 24835, 24950, 24835, 24950, 60140, 60140, 53, "TDD"),
            (65, 21100, 22000, 19200, 20100, 65536, 131072, 65, "FDD"),
            (66, 21100, 22000, 17100, 17800, 66436, 131972, 66, "FDD"),
            (67, 7380, 7580, LTE_FREQ_INV, LTE_FREQ_INV, 67336, LTE_EARFCN_INV, 67, "SDL"),
            (68, 7530, 7830, 6980, 7280, 67536, 132672, 68, "FDD"),
            (69, 25700, 26200, LTE_FREQ_INV, LTE_FREQ_INV, 67836, LTE_EARFCN_INV, 69, "SDL"),
            (70, 19950, 20200, 16950, 17100, 68336, 132972, 70, "FDD"),
            (71, 6170, 6520, 6630, 6980, 68586, 133122, 71, "FDD"),
            (72, 4610, 4660, 4510, 4560, 68936, 133472, 72, "FDD"),
            (73, 4600, 4650, 4500, 4550, 68986, 133522, 73, "FDD"),
            (74, 14750, 15180, 14270, 14700, 69036, 133572, 74, "FDD"),
            (75, 14320, 15170, LTE_FREQ_INV, LTE_FREQ_INV, 69466, LTE_EARFCN_INV, 75, "SDL"),
            (76, 14270, 14320, LTE_FREQ_INV, LTE_FREQ_INV, 70316, LTE_EARFCN_INV, 76, "SDL"),
            (85, 7280, 7460, 6980, 7160, 70366, 134002, 85, "FDD"),
            (87, 4200, 4250, 4100, 4150, 70546, 134182, 87, "FDD"),
            (88, 4220, 4270, 4120, 4170, 70596, 134232, 88, "FDD"),
        ]

        for band, dl_low, dl_high, ul_low, ul_high, dl_earfcn_low, ul_earfcn_low, band_num, duplex_mode in bands:
            if dl_low == LTE_FREQ_INV or dl_earfcn_low == LTE_EARFCN_INV:
                continue
            dl_bw = dl_high - dl_low
            dl_earfcn_high = dl_earfcn_low + dl_bw
            ul_bw = ul_high - ul_low if ul_high != LTE_FREQ_INV else dl_bw
            ul_earfcn_high = ul_earfcn_low + ul_bw if duplex_mode != "SDL" else dl_earfcn_high if duplex_mode == "TDD" else ul_earfcn_low + ul_bw

            # Check if EARFCN matches DL or UL range
            if dl_earfcn_low <= earfcn <= dl_earfcn_high:
                dl_earfcn = earfcn
                ul_earfcn = dl_earfcn + (ul_earfcn_low - dl_earfcn_low) if duplex_mode == "FDD" else dl_earfcn if duplex_mode == "TDD" else "N/A"
            elif ul_earfcn_low <= earfcn <= ul_earfcn_high and duplex_mode != "SDL":
                ul_earfcn = earfcn
                dl_earfcn = ul_earfcn - (ul_earfcn_low - dl_earfcn_low) if duplex_mode == "FDD" else ul_earfcn if duplex_mode == "TDD" else "N/A"
            else:
                continue

            # Calculate frequencies
            dl_freq = dl_low + (dl_earfcn - dl_earfcn_low)
            dl_freq_mhz = dl_freq / 10.0
            if duplex_mode == "SDL":
                ul_freq_mhz = "N/A"
            elif duplex_mode == "TDD":
                ul_freq_mhz = dl_freq_mhz
            else:  # FDD
                ul_offset = ul_low - dl_low
                ul_freq = dl_freq + ul_offset
                ul_freq_mhz = ul_freq / 10.0

            # Format result with both DL and UL details
            result = f"DL Freq: {dl_freq_mhz:.1f} MHz\nUL Freq: {ul_freq_mhz if isinstance(ul_freq_mhz, str) else f'{ul_freq_mhz:.1f}'} MHz\nDL EARFCN: {dl_earfcn}\nUL EARFCN: {ul_earfcn}\nBand: {band_num}\nMode: {duplex_mode}"
            logs.append(result)
            dl_range = f"{dl_earfcn_low}-{dl_earfcn_high}"
            ul_range = f"{ul_earfcn_low}-{ul_earfcn_high}" if duplex_mode != "SDL" else "N/A"
            band_table = f"Band: {band_num}, DL EARFCN: {dl_range}, UL EARFCN: {ul_range}, Mode: {duplex_mode}"
            logs.append(band_table)
            return result, logs

        result = f"No band found for EARFCN {earfcn}. Please verify the EARFCN is valid."
        logs.append(result)
        return result, logs

    except ValueError:
        result = "Error: Invalid input: Please enter a valid integer EARFCN without units."
        logs.append(result)
        return result, logs




def weight_ava(numbers):
    logs = []
    try:
        num_subjects = numbers[0] if numbers and numbers[0] else None
        if not num_subjects or num_subjects == '':
            return "Error: Please select a number of subjects", ['Error: No subject count provided']
        num_subjects = int(num_subjects)
        if num_subjects not in [1, 2, 3, 4]:
            return "Error: Number of subjects must be 1, 2, 3, or 4", ['Error: Invalid number of subjects']
        if len(numbers) - 1 < num_subjects:
            return "Error: Insufficient scores provided", ['Error: Insufficient scores']

        scores = []
        for i in range(num_subjects):
            try:
                score = float(numbers[i + 1])
                if score < 0:
                    return "Error: Scores must be non-negative", ['Error: Scores must be non-negative']
                scores.append(score)
                logs.append(f'Subject {i+1}: Score = {score}')
            except (ValueError, IndexError):
                return "Error: Invalid input", ['Error: Scores must be numeric']

        average = sum(scores) / num_subjects
        average = round(average, 2)
        logs.append(f'Average = {average}')
        return str(average), logs

    except Exception as e:
        return "Error: Processing failed", [f'Error: {str(e)}']

      
def test_api(numbers):
    """
    It will take TE SFN no. to UE SFN number  

    """
    logs = []
    number = numbers
    logs.append("------------------------")  # Log message for Box D
    try:
        #TE_SFN = int(numbers[0])  # Power in dBm

        result = str(number)
        logs.append(f"testing sucessful : {result} ")  # Log message for Box D

        return str(result), logs
        
    except ValueError as e:
        error_msg = "Invalid input. Please enter valid numbers."
        logs.append(f"Error: {error_msg}")
        return f"Error: {error_msg}", logs
    



def lte_dl_tput_calculations(numbers):
    """
    It will take TE SFN no. to UE SFN number  

    """
    logs = []
    logs.append("Convert TE SFN to UE SFN in terms of %1024...")  # Log message for Box D
    try:
        TE_SFN = int(numbers[0])  # Power in dBm

        result = TE_SFN % 1024  # Example: 2 dBm loss per km
        return str(result), logs
    except ValueError as e:
        error_msg = "Invalid input. Please enter valid numbers."
        logs.append(f"Error: {error_msg}")
        return f"Error: {error_msg}", logs


def el1_rx_cal(numbers):

    logs = []
    logs.append("----------------------------------")
    

    try:
        results = None
        if numbers['channel_type'] == '1':
            #lte_idle_mode_paging_calculations
            #{'channel_type': '1', 'mode': 'FDD', 'nb_value': '2T', 't_value': '32', 'UE_ID': '1'}

            def n_ns_value(nb,T):
                n_maping = {"4T":T, "2T":T, "T":T, "1/2T" : T/2, "1/4T": T/4, "1/8T": T/8, "1/16T": T/16 , "1/32T": T/32     }
                N = int(n_maping[nB])
                
                #Ns = max(1, nB/T)
                nb_int_value = {"4T":4*T, "2T":2*T, "T":T, "1/2T" : 1/2*T, "1/4T": 1/4*T, "1/8T": 1/8*T, "1/16T": 1/16*T , "1/32T": 1/32*T     }
                Ns = int(max(1,nb_int_value[nb]/T))
                print("--------------------------------------------")
                print(f"-----> N,Ns :   {N}, {Ns}",)
                return N,Ns

            
            mode = numbers['mode']
            nB= numbers["nb_value"]
            t = int(numbers["t_value"])
            ue_id = int(numbers['UE_ID'])

            N,Ns = n_ns_value(nB,t)
            
            UEID_MOD_N = ue_id % N

            logs.append(f"   N value : {N}")
            logs.append(f"  UE_ID Mod N value : {UEID_MOD_N}")
            
            PF_Index = int(( (t/N) * (UEID_MOD_N) ))
            start_sfn = int(( (t/N) * (UEID_MOD_N) ))

            logs.append(f"  PF_Index (Starting SFN number) : {PF_Index}")


            def extract_until_second_occurrence(lst):
                first_value = lst[0]
                count = 0
                for i, val in enumerate(lst):
                    if val == first_value:
                        count += 1
                        if count == 2:
                            return lst[:i+1]
                return lst  # return full list if second occurrence not found

            frame_output = []
            for i in range(70):
                frame_output.append(int(PF_Index))

                if int(PF_Index) >= 1024:
                    PF_Index = PF_Index - 1024
                    frame_output.append(int(PF_Index))
                PF_Index = PF_Index + t

            filtered_list  = [value for value in frame_output if value <1024]
            subframe = 23

            #i_s = Floor(ue_id / N) mod Ns
            i_s = int( ( math.floor(ue_id/N)) % (Ns))
            

            def sf_find(mode,Ns,i_s):
                values = (Ns,i_s)
                fdd_value = { (1,0) : 9,
                        (1,1) : "NA",
                        (1,2) : "NA",
                        (1,3) : "NA",
                        (2,0) : 4,
                        (2,1) : 9 ,
                        (2,2) : "NA",
                        (2,3) : "NA",
                        (4,0) : 0,
                        (4,1) : 4,
                        (4,2) : 5,
                        (4,3) : 9   }
                
                tdd_value = { (1,0) : 0,
                        (1,1) : "NA",
                        (1,2) : "NA",
                        (1,3) : "NA",
                        (2,0) : 0,
                        (2,1) : 5 ,
                        (2,2) : "NA",
                        (2,3) : "NA",
                        (4,0) : 0,
                        (4,1) : 1,
                        (4,2) : 5,
                        (4,3) : 6   }


                if mode == "FDD":
                    Subframe_number = fdd_value[(Ns,i_s)]

                if mode == "TDD":
                    Subframe_number = tdd_value[(Ns,i_s)]
                
                return Subframe_number
            
            logs.append(f"  (Ns, i_s) : ({Ns},{i_s})")
            logs.append(f" Subframe Number :  {sf_find(mode,Ns,i_s)}")
            logs.append(f" SFN Sequnnce list: {extract_until_second_occurrence(filtered_list)}")


            results = f" \nStarting SFN : {start_sfn} \n SubFrame Numer : {sf_find(mode,Ns,i_s)}, \n SFN Sequnnce list: {extract_until_second_occurrence(filtered_list)}  "


        

        logs.append(results) 
        
        return str(results), logs
    
    except ValueError as e:
        error_msg = "Invalid input. Please enter valid numbers (only int/float values)."
        logs.append(f"Error: {error_msg} {e}")
        return f"Error: {error_msg}", logs



def get_lte_band_info(numbers):
    """
    Returns a dictionary containing LTE band parameters for the given band number.
    Args:
        numbers (list): List containing the LTE band number (e.g., ['1']).
    Returns:
        tuple: (result string, logs list) containing band info or error message.
    """
    logs = []
    logs.append("------------------------")  # Log message for Box D

    # Dictionary of LTE bands based on provided tables
    lte_bands = {
        1: {
            "Band": 1,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "2100",
            "Common Name": "IMT",
            "Subset of Band": "65",
            "Uplink(MHz)": "1920 - 1980",
            "Downlink(MHz)": "2110 - 2170",
            "Duplex Spacing(MHz)": "190",
            "Channel Bandwidths(MHz)": "5, 10, 15, 20",
            "Notes": ""
        },
        2: {
            "Band": 2,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "1900",
            "Common Name": "PCS",
            "Subset of Band": "25",
            "Uplink(MHz)": "1850 - 1910",
            "Downlink(MHz)": "1930 - 1990",
            "Duplex Spacing(MHz)": "80",
            "Channel Bandwidths(MHz)": "1.4, 3, 5, 10, 15, 20",
            "Notes": ""
        },
        3: {
            "Band": 3,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "1800",
            "Common Name": "DCS",
            "Subset of Band": "",
            "Uplink(MHz)": "1710 - 1785",
            "Downlink(MHz)": "1805 - 1880",
            "Duplex Spacing(MHz)": "95",
            "Channel Bandwidths(MHz)": "1.4, 3, 5, 10, 15, 20",
            "Notes": ""
        },
        4: {
            "Band": 4,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "1700",
            "Common Name": "AWS-1",
            "Subset of Band": "10, 66",
            "Uplink(MHz)": "1710 - 1755",
            "Downlink(MHz)": "2110 - 2155",
            "Duplex Spacing(MHz)": "400",
            "Channel Bandwidths(MHz)": "1.4, 3, 5, 10, 15, 20",
            "Notes": ""
        },
        5: {
            "Band": 5,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "850",
            "Common Name": "Cellular",
            "Subset of Band": "26",
            "Uplink(MHz)": "824 - 849",
            "Downlink(MHz)": "869 - 894",
            "Duplex Spacing(MHz)": "45",
            "Channel Bandwidths(MHz)": "1.4, 3, 5, 10",
            "Notes": ""
        },
        6: {
            "Band": 6,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "800",
            "Common Name": "UMTS 800",
            "Subset of Band": "5, 19, 26",
            "Uplink(MHz)": "830 - 840",
            "Downlink(MHz)": "875 - 885",
            "Duplex Spacing(MHz)": "45",
            "Channel Bandwidths(MHz)": "5, 10",
            "Notes": ""
        },
        7: {
            "Band": 7,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "2600",
            "Common Name": "IMT-E",
            "Subset of Band": "",
            "Uplink(MHz)": "2500 - 2570",
            "Downlink(MHz)": "2620 - 2690",
            "Duplex Spacing(MHz)": "120",
            "Channel Bandwidths(MHz)": "5, 10, 15, 20",
            "Notes": ""
        },
        8: {
            "Band": 8,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "900",
            "Common Name": "Extended GSM",
            "Subset of Band": "",
            "Uplink(MHz)": "880 - 915",
            "Downlink(MHz)": "925 - 960",
            "Duplex Spacing(MHz)": "45",
            "Channel Bandwidths(MHz)": "1.4, 3, 5, 10",
            "Notes": ""
        },
        9: {
            "Band": 9,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "1800",
            "Common Name": "UMTS 1700",
            "Subset of Band": "3",
            "Uplink(MHz)": "1749.9 - 1784.9",
            "Downlink(MHz)": "1844.9 - 1879.9",
            "Duplex Spacing(MHz)": "95",
            "Channel Bandwidths(MHz)": "5, 10",
            "Notes": ""
        },
        10: {
            "Band": 10,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "1700",
            "Common Name": "Extended AWS",
            "Subset of Band": "66",
            "Uplink(MHz)": "1710 - 1770",
            "Downlink(MHz)": "2110 - 2170",
            "Duplex Spacing(MHz)": "400",
            "Channel Bandwidths(MHz)": "5, 10, 15, 20",
            "Notes": ""
        },
        11: {
            "Band": 11,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "1500",
            "Common Name": "Lower PDC",
            "Subset of Band": "74",
            "Uplink(MHz)": "1427.9 - 1447.9",
            "Downlink(MHz)": "1475.9 - 1495.9",
            "Duplex Spacing(MHz)": "48",
            "Channel Bandwidths(MHz)": "5, 10",
            "Notes": "Japan"
        },
        12: {
            "Band": 12,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "700",
            "Common Name": "Lower SMH",
            "Subset of Band": "85",
            "Uplink(MHz)": "699 - 716",
            "Downlink(MHz)": "729 - 746",
            "Duplex Spacing(MHz)": "30",
            "Channel Bandwidths(MHz)": "1.4, 3, 5, 10",
            "Notes": ""
        },
        13: {
            "Band": 13,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "700",
            "Common Name": "Upper SMH",
            "Subset of Band": "",
            "Uplink(MHz)": "777 - 787",
            "Downlink(MHz)": "746 - 756",
            "Duplex Spacing(MHz)": "-31",
            "Channel Bandwidths(MHz)": "5, 10",
            "Notes": ""
        },
        14: {
            "Band": 14,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "700",
            "Common Name": "Upper SMH",
            "Subset of Band": "",
            "Uplink(MHz)": "788 - 798",
            "Downlink(MHz)": "758 - 768",
            "Duplex Spacing(MHz)": "-30",
            "Channel Bandwidths(MHz)": "5, 10",
            "Notes": ""
        },
        17: {
            "Band": 17,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "700",
            "Common Name": "Lower SMH",
            "Subset of Band": "12, 85",
            "Uplink(MHz)": "704 - 716",
            "Downlink(MHz)": "734 - 746",
            "Duplex Spacing(MHz)": "30",
            "Channel Bandwidths(MHz)": "5, 10",
            "Notes": ""
        },
        18: {
            "Band": 18,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "850",
            "Common Name": "Lower 800",
            "Subset of Band": "26",
            "Uplink(MHz)": "815 - 830",
            "Downlink(MHz)": "860 - 875",
            "Duplex Spacing(MHz)": "45",
            "Channel Bandwidths(MHz)": "5, 10, 15",
            "Notes": "Japan"
        },
        19: {
            "Band": 19,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "850",
            "Common Name": "Upper 800",
            "Subset of Band": "5, 26",
            "Uplink(MHz)": "830 - 845",
            "Downlink(MHz)": "875 - 890",
            "Duplex Spacing(MHz)": "45",
            "Channel Bandwidths(MHz)": "5, 10, 15",
            "Notes": "Japan"
        },
        20: {
            "Band": 20,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "800",
            "Common Name": "Digital Dividend",
            "Subset of Band": "",
            "Uplink(MHz)": "832 - 862",
            "Downlink(MHz)": "791 - 821",
            "Duplex Spacing(MHz)": "-41",
            "Channel Bandwidths(MHz)": "5, 10, 15, 20",
            "Notes": "EU"
        },
        21: {
            "Band": 21,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "1500",
            "Common Name": "Upper PDC",
            "Subset of Band": "74",
            "Uplink(MHz)": "1447.9 - 1462.9",
            "Downlink(MHz)": "1495.9 - 1510.9",
            "Duplex Spacing(MHz)": "48",
            "Channel Bandwidths(MHz)": "5, 10, 15",
            "Notes": "Japan"
        },
        22: {
            "Band": 22,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "3500",
            "Common Name": "C-Band",
            "Subset of Band": "",
            "Uplink(MHz)": "3410 - 3500",
            "Downlink(MHz)": "3510 - 3600",
            "Duplex Spacing(MHz)": "100",
            "Channel Bandwidths(MHz)": "5, 10, 15, 20",
            "Notes": ""
        },
        23: {
            "Band": 23,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "2000",
            "Common Name": "AWS-4",
            "Subset of Band": "",
            "Uplink(MHz)": "2000 - 2020",
            "Downlink(MHz)": "2180 - 2200",
            "Duplex Spacing(MHz)": "180",
            "Channel Bandwidths(MHz)": "1.4, 3, 5, 10, 15, 20",
            "Notes": ""
        },
        24: {
            "Band": 24,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "1600",
            "Common Name": "Upper L-Band",
            "Subset of Band": "",
            "Uplink(MHz)": "1626.5 - 1660.5",
            "Downlink(MHz)": "1525 - 1559",
            "Duplex Spacing(MHz)": "-101.5 or -120.5",
            "Channel Bandwidths(MHz)": "5, 10",
            "Notes": "US"
        },
        25: {
            "Band": 25,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "1900",
            "Common Name": "Extended PCS",
            "Subset of Band": "",
            "Uplink(MHz)": "1850 - 1915",
            "Downlink(MHz)": "1930 - 1995",
            "Duplex Spacing(MHz)": "80",
            "Channel Bandwidths(MHz)": "1.4, 3, 5, 10, 15, 20",
            "Notes": ""
        },
        26: {
            "Band": 26,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "850",
            "Common Name": "Extended Cellular",
            "Subset of Band": "",
            "Uplink(MHz)": "814 - 849",
            "Downlink(MHz)": "859 - 894",
            "Duplex Spacing(MHz)": "45",
            "Channel Bandwidths(MHz)": "1.4, 3, 5, 10, 15",
            "Notes": ""
        },
        27: {
            "Band": 27,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "800",
            "Common Name": "SMR",
            "Subset of Band": "",
            "Uplink(MHz)": "807 - 824",
            "Downlink(MHz)": "852 - 869",
            "Duplex Spacing(MHz)": "45",
            "Channel Bandwidths(MHz)": "1.4, 3, 5, 10",
            "Notes": "US"
        },
        28: {
            "Band": 28,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "700",
            "Common Name": "APT",
            "Subset of Band": "",
            "Uplink(MHz)": "703 - 748",
            "Downlink(MHz)": "758 - 803",
            "Duplex Spacing(MHz)": "55",
            "Channel Bandwidths(MHz)": "3, 5, 10, 15, 20",
            "Notes": ""
        },
        29: {
            "Band": 29,
            "Duplex Mode": "SDL",
            "Frequency(MHz)": "700",
            "Common Name": "Lower SMH",
            "Subset of Band": "44",
            "Uplink(MHz)": "—",
            "Downlink(MHz)": "717 - 728",
            "Duplex Spacing(MHz)": "—",
            "Channel Bandwidths(MHz)": "3, 5, 10",
            "Notes": ""
        },
        30: {
            "Band": 30,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "2300",
            "Common Name": "WCS",
            "Subset of Band": "",
            "Uplink(MHz)": "2305 - 2315",
            "Downlink(MHz)": "2350 - 2360",
            "Duplex Spacing(MHz)": "45",
            "Channel Bandwidths(MHz)": "5, 10",
            "Notes": ""
        },
        31: {
            "Band": 31,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "450",
            "Common Name": "NMT",
            "Subset of Band": "",
            "Uplink(MHz)": "452.5 - 457.5",
            "Downlink(MHz)": "462.5 - 467.5",
            "Duplex Spacing(MHz)": "10",
            "Channel Bandwidths(MHz)": "1.4, 3, 5",
            "Notes": ""
        },
        32: {
            "Band": 32,
            "Duplex Mode": "SDL",
            "Frequency(MHz)": "1500",
            "Common Name": "L-Band",
            "Subset of Band": "75",
            "Uplink(MHz)": "—",
            "Downlink(MHz)": "1452 - 1496",
            "Duplex Spacing(MHz)": "—",
            "Channel Bandwidths(MHz)": "5, 10, 15, 20",
            "Notes": "EU"
        },
        33: {
            "Band": 33,
            "Duplex Mode": "TDD",
            "Frequency(MHz)": "1900",
            "Common Name": "IMT",
            "Subset of Band": "39",
            "Uplink(MHz)": "1900 - 1920",
            "Downlink(MHz)": "1900 - 1920",
            "Duplex Spacing(MHz)": "—",
            "Channel Bandwidths(MHz)": "5, 10, 15, 20",
            "Notes": ""
        },
        34: {
            "Band": 34,
            "Duplex Mode": "TDD",
            "Frequency(MHz)": "2000",
            "Common Name": "IMT",
            "Subset of Band": "",
            "Uplink(MHz)": "2010 - 2025",
            "Downlink(MHz)": "2010 - 2025",
            "Duplex Spacing(MHz)": "—",
            "Channel Bandwidths(MHz)": "5, 10, 15",
            "Notes": ""
        },
        35: {
            "Band": 35,
            "Duplex Mode": "TDD",
            "Frequency(MHz)": "1900",
            "Common Name": "PCS",
            "Subset of Band": "",
            "Uplink(MHz)": "1850 - 1910",
            "Downlink(MHz)": "1850 - 1910",
            "Duplex Spacing(MHz)": "—",
            "Channel Bandwidths(MHz)": "1.4, 3, 5, 10, 15, 20",
            "Notes": "PCS Uplink"
        },
        36: {
            "Band": 36,
            "Duplex Mode": "TDD",
            "Frequency(MHz)": "1900",
            "Common Name": "PCS",
            "Subset of Band": "",
            "Uplink(MHz)": "1930 - 1990",
            "Downlink(MHz)": "1930 - 1990",
            "Duplex Spacing(MHz)": "—",
            "Channel Bandwidths(MHz)": "1.4, 3, 5, 10, 15, 20",
            "Notes": "PCS Downlink"
        },
        37: {
            "Band": 37,
            "Duplex Mode": "TDD",
            "Frequency(MHz)": "1900",
            "Common Name": "PCS",
            "Subset of Band": "",
            "Uplink(MHz)": "1910 - 1930",
            "Downlink(MHz)": "1910 - 1930",
            "Duplex Spacing(MHz)": "—",
            "Channel Bandwidths(MHz)": "5, 10, 15, 20",
            "Notes": "PCS Duplex Spacing"
        },
        38: {
            "Band": 38,
            "Duplex Mode": "TDD",
            "Frequency(MHz)": "2600",
            "Common Name": "IMT-E",
            "Subset of Band": "41",
            "Uplink(MHz)": "2570 - 2620",
            "Downlink(MHz)": "2570 - 2620",
            "Duplex Spacing(MHz)": "—",
            "Channel Bandwidths(MHz)": "5, 10, 15, 20",
            "Notes": "IMT-E Duplex Spacing"
        },
        39: {
            "Band": 39,
            "Duplex Mode": "TDD",
            "Frequency(MHz)": "1900",
            "Common Name": "DCS-IMT Gap",
            "Subset of Band": "",
            "Uplink(MHz)": "1880 - 1920",
            "Downlink(MHz)": "1880 - 1920",
            "Duplex Spacing(MHz)": "—",
            "Channel Bandwidths(MHz)": "5, 10, 15, 20",
            "Notes": ""
        },
        40: {
            "Band": 40,
            "Duplex Mode": "TDD",
            "Frequency(MHz)": "2300",
            "Common Name": "S-Band",
            "Subset of Band": "",
            "Uplink(MHz)": "2300 - 2400",
            "Downlink(MHz)": "2300 - 2400",
            "Duplex Spacing(MHz)": "—",
            "Channel Bandwidths(MHz)": "5, 10, 15, 20",
            "Notes": ""
        },
        41: {
            "Band": 41,
            "Duplex Mode": "TDD",
            "Frequency(MHz)": "2500",
            "Common Name": "BRS",
            "Subset of Band": "",
            "Uplink(MHz)": "2496 - 2690",
            "Downlink(MHz)": "2496 - 2690",
            "Duplex Spacing(MHz)": "—",
            "Channel Bandwidths(MHz)": "5, 10, 15, 20",
            "Notes": "US"
        },
        42: {
            "Band": 42,
            "Duplex Mode": "TDD",
            "Frequency(MHz)": "3500",
            "Common Name": "CBRS",
            "Subset of Band": "",
            "Uplink(MHz)": "3400 - 3600",
            "Downlink(MHz)": "3400 - 3600",
            "Duplex Spacing(MHz)": "—",
            "Channel Bandwidths(MHz)": "5, 10, 15, 20",
            "Notes": "EU, Japan"
        },
        43: {
            "Band": 43,
            "Duplex Mode": "TDD",
            "Frequency(MHz)": "3700",
            "Common Name": "C-Band",
            "Subset of Band": "",
            "Uplink(MHz)": "3600 - 3800",
            "Downlink(MHz)": "3600 - 3800",
            "Duplex Spacing(MHz)": "—",
            "Channel Bandwidths(MHz)": "5, 10, 15, 20",
            "Notes": ""
        },
        44: {
            "Band": 44,
            "Duplex Mode": "TDD",
            "Frequency(MHz)": "700",
            "Common Name": "APT",
            "Subset of Band": "",
            "Uplink(MHz)": "703 - 803",
            "Downlink(MHz)": "703 - 803",
            "Duplex Spacing(MHz)": "—",
            "Channel Bandwidths(MHz)": "3, 5, 10, 15, 20",
            "Notes": ""
        },
        45: {
            "Band": 45,
            "Duplex Mode": "TDD",
            "Frequency(MHz)": "1500",
            "Common Name": "L-Band",
            "Subset of Band": "50",
            "Uplink(MHz)": "1447 - 1467",
            "Downlink(MHz)": "1447 - 1467",
            "Duplex Spacing(MHz)": "—",
            "Channel Bandwidths(MHz)": "5, 10, 15, 20",
            "Notes": ""
        },
        46: {
            "Band": 46,
            "Duplex Mode": "TDD",
            "Frequency(MHz)": "5200",
            "Common Name": "U-NII-1-4",
            "Subset of Band": "",
            "Uplink(MHz)": "5150 - 5925",
            "Downlink(MHz)": "5150 - 5925",
            "Duplex Spacing(MHz)": "—",
            "Channel Bandwidths(MHz)": "10, 20",
            "Notes": "LAA"
        },
        49: {
            "Band": 49,
            "Duplex Mode": "TDD",
            "Frequency(MHz)": "3500",
            "Common Name": "C-Band",
            "Subset of Band": "48",
            "Uplink(MHz)": "3550 - 3700",
            "Downlink(MHz)": "3550 - 3700",
            "Duplex Spacing(MHz)": "—",
            "Channel Bandwidths(MHz)": "10, 20",
            "Notes": ""
        },
        52: {
            "Band": 52,
            "Duplex Mode": "TDD",
            "Frequency(MHz)": "3300",
            "Common Name": "C-Band",
            "Subset of Band": "",
            "Uplink(MHz)": "3300 - 3400",
            "Downlink(MHz)": "3300 - 3400",
            "Duplex Spacing(MHz)": "—",
            "Channel Bandwidths(MHz)": "5, 10, 15, 20",
            "Notes": ""
        },
        68: {
            "Band": 68,
            "Duplex Mode": "FDD",
            "Frequency(MHz)": "700",
            "Common Name": "ME 700",
            "Subset of Band": "",
            "Uplink(MHz)": "698 - 728",
            "Downlink(MHz)": "753 - 783",
            "Duplex Spacing(MHz)": "55",
            "Channel Bandwidths(MHz)": "5, 10, 15",
            "Notes": "MEA"
        },
        252: {
            "Band": 252,
            "Duplex Mode": "SDL",
            "Frequency(MHz)": "5200",
            "Common Name": "U-NII-1",
            "Subset of Band": "",
            "Uplink(MHz)": "—",
            "Downlink(MHz)": "5150 - 5250",
            "Duplex Spacing(MHz)": "—",
            "Channel Bandwidths(MHz)": "5, 10, 15, 20",
            "Notes": "LTE-U"
        },
        255: {
            "Band": 255,
            "Duplex Mode": "SDL",
            "Frequency(MHz)": "5800",
            "Common Name": "U-NII-3",
            "Subset of Band": "",
            "Uplink(MHz)": "—",
            "Downlink(MHz)": "5725 - 5850",
            "Duplex Spacing(MHz)": "—",
            "Channel Bandwidths(MHz)": "5, 10, 15, 20",
            "Notes": "LTE-U"
        }
    }
    


    def to_string(data):
        if data is None:
            return "Band info not available. Please verify if the band number is valid."
        return '\n'.join(f"{key}: {value}" for key, value in data.items())

    try:
        if not numbers or 'band' not in numbers or not numbers['band']:
            raise ValueError("No band number provided")
        
        band_number = int(numbers['band'])
        band_data = lte_bands.get(band_number)

        if not band_data:
            logs.append("Band not found in predefined LTE bands.")

        result = to_string(band_data)
        logs.append(result)
        return result, logs

    except ValueError as e:
        error_msg = f"Invalid Band. {str(e)} Please cross verify whether entered band is valid."
        logs.append(f"Error: {error_msg}")
        return error_msg, logs

    except Exception as e:
        error_msg = f"Error processing request: {str(e)}"
        logs.append(f"Error: {error_msg}")
        return error_msg, logs