

// Calculator templates with domains
const calculators = {
    'GET-BNAD-INFO': {
        title: 'Get Band Info',
        domain: 'Telecom',
        inputs: [
            { label: 'Band', id: 'band', type: 'text', validation: { required: true, type: 'int', customErrorMessage: 'band must be a valid integer.' } },
        ],
        popupText: 'Enter band to get full details about it. '
    },

    'CONV-EARFCN-FREQ': {
        title: 'Convert EARFCN to DL Freq',
        domain: 'Telecom',
        inputs: [
            { label: 'Enter EARFCN ( from 0 to 65535)', id: 'earfcn', type: 'text', validation: { required: true, type: 'int', customErrorMessage: 'EARFCN must be a valid integer.' } },
        ],
        popupText: "The Calculator converts an EARFCN to its corresponding downlink frequency (in units of 0.1 MHz) for LTE bands. \n\n Example: (in 0.1 MHz units, e.g., 21100 = 2110.0 MHz) \n\n\Note : present support from Band1 to Band 46.  "
    },

    'two-db-total-power': {
        title: "Total Power of Two db's",
        domain: 'Telecom',
        inputs: [
            { label: 'dB1 value', id: 'db1', type: 'text' , validation: { required: true, type: 'int', customErrorMessage: 'dB1 must be a valid integer.' }},
            { label: 'dB2 value', id: 'db2', type: 'text', validation: { required: true, type: 'int', customErrorMessage: 'dB1 must be a valid integer.' } },
        ],
        popupText: "This caculator will help us to calculate the total power of two db's. \n\n Example: \n dB1 = 19dB \n dB2 = 19dB \n Total Power =  22.010299 dB"
    },

    'el1-rx-cal': {
        title: "[LTE][PHY] RX Calculator..",
        domain: 'Telecom',
        inputs: [
            {   
                label: 'Select the Calculator? ', 
                id: 'lte-rx-cal', 
                type: 'dropdown', 
                options: [
                    { value: '', label: 'Select' },
                    { value: '1', label: 'Idle mode paging calc..' },
                    
                ]
            }
        ],


    subjectMappings: {
        1: [
            { 
                label: 'Mode', 
                id: 'mode', 
                type: 'dropdown', 
                options: [
                    { value: '', label: 'Select the Duplex Mode Type' },
                    { value: 'FDD', label: 'FDD' },
                    { value: 'TDD', label: 'TDD' },
                ]
            },
            { 
                label: 'nB value', 
                id: 'nb_value', 
                type: 'dropdown', 
                options: [
                    { value: '', label: 'Select the nB vlue' },
                    { value: "4T", label: '4T' },
                    { value: '2T', label: '2T' },
                    { value: "T", label: 'T' },
                    { value: '1/2T', label: '1/2T' },
                    { value: "1/4T", label: '1/4T' },
                    { value: '1/8T', label: '1/8T' },
                    { value: "1/16T", label: '1/16T' },
                    { value: '1/32T', label: '1/32T' },
                ]
            },
            { 
                label: 'T (dRX Cycle lenght) value', 
                id: 't_value', 
                type: 'dropdown', 
                options: [
                    { value: '', label: 'Select the DRX Cycle lenght' },
                    { value: "16", label: '16' },
                    { value: '32', label: '32' },
                    { value: "64", label: '64' },
                    { value: '128', label: '128' },
                    { value: "256", label: '256' },
                ]
            },
            { label: 'UE_ID (IMSI mod 1024) ', id: 'UE_ID', type: 'text', validation: { required: true, type: 'int', customErrorMessage: 'ue id  must be a valid integer.' }  },
        ],

    },

        popupText: "parch_cal_pwr = Preamble_init_power + (preamble_transmission_counter-1) * power_ramping_step + pl  \n pucch_cal_pwr  = (p_zero_nom_pucch + p_ue_PUCCH_id) + pl + PucchFrm_h + delta_f + g_i \n pusch_cal_pwr = log_m_pusch + ( p0_num_pusch + p0_ue_pusch) + alpha_final * pl + delta_tf + f_i \n msg3_tx_pwr = log_m_pusch + (Preamble_init_power + delta_msg3) + pl + f_0 \n srs_power = P_SRS_Offset + log_m_srs + (p0_num_pusch  + P0_UE_PUSCH) + final_alpha * pl + f_i"
    },



    'el1-tx-power': {
        title: "[LTE][PHY] TX Calculator..",
        domain: 'Telecom',
        inputs: [
            {   
                label: 'Select the Calculator ..? ', 
                id: 'tx-ch-power', 
                type: 'dropdown', 
                options: [
                    { value: '', label: 'Select' },
                    { value: '1', label: 'PRACH Power calc..' },
                    { value: '2', label: 'PUCCH Power calc..' },
                    { value: '3', label: 'PUSCH Power calc..' },
                    { value: '4', label: 'MSG3 TX power calc..' },
                    { value: '5', label: 'SRS power Calc..' },
                    { value: '6', label: 'Periodic CSI Occasion Cal..' },
                    
                ]
            }
        ],



    subjectMappings: {
        1: [
            { label: 'Preamble_init_power', id: 'Preamble_init_power-id', type: 'text', validation: { required: true, type: 'int', customErrorMessage: 'Preamble_init_power must be a valid integer.' } },
            { label: 'Preamble_transmission_counter', id: 'preamble_transmission_counter-id', type: 'text', validation: { required: true, type: 'int', customErrorMessage: 'Preamble_transmission_counter must be a valid integer.' } },
            { label: 'Power_ramping_step', id: 'power_ramping_step-id', type: 'text', validation: { required: true, type: 'int', customErrorMessage: 'Power_ramping_step must be a valid integer.' }  },
            { label: 'Poth Loss (PL)', id: 'Poth_loss-id-1', type: 'text', validation: { required: true, type: 'int', customErrorMessage: 'Poth Loss (PL) must be a valid integer.' }  },
            { label: 'Pcmax', id: 'Pcmax-id-1', type: 'text', optional: true, validation: { type: 'int', customErrorMessage: 'Pcmax must be a valid integer.' } }

        ],
        2: [
            { label: 'P0_nom_PUCCH', id: '0_nom_PUCCH-id', type: 'text' , validation: { required: true, type: 'int', customErrorMessage: 'P0_nom_PUCCH must be a valid integer.' } },
            { label: 'P0_ue_PUCCH', id: 'P0_ue_PUCCH-id', type: 'text', validation: { required: true, type: 'int', customErrorMessage: 'P0_ue_PUCCH must be a valid integer.' }  },
            { label: 'path Loss (PL)', id: 'pl-id', type: 'text', validation: { required: true, type: 'int', customErrorMessage: 'path Loss (PL) must be a valid integer.' }  },
            { label: 'PucchFrm_h', id: 'PucchFrm_h', type: 'text', validation: { required: true, type: 'int', customErrorMessage: 'PucchFrm_h must be a valid integer.' }  },
            { label: 'delta_f', id: 'delta_f-id', type: 'text', validation: { required: true, type: 'int', customErrorMessage: 'delta_f must be a valid integer.' }  },
            { label: 'g(i)', id: 'g_i-id', type: 'text', validation: { required: true, type: 'int', customErrorMessage: 'g(i) must be a valid integer.' }  },
            { label: 'Pcmax', id: 'Pcmax-id-2', type: 'text', optional: true , validation: { type: 'int', customErrorMessage: 'Pcmax must be a valid integer.' }}

        ],
        3: [
            { label: 'log_m_pusch', id: 'log_m_pusch-id', type: 'text', validation: { required: true, type: 'int', customErrorMessage: 'log_m_pusch must be a valid integer.' }  },
            { label: 'P0_nom_PUSCH', id: 'P0_nom_PUSCH-id', type: 'text', validation: { required: true, type: 'int', customErrorMessage: 'P0_nom_PUSCH must be a valid integer.' }  },
            { label: 'P0_ue_PUSCH', id: 'P0_ue_PUSCH-id', type: 'text', validation: { required: true, type: 'int', customErrorMessage: 'P0_ue_PUSCH must be a valid integer.' }  },
            {   
                label: 'Alpha value ', 
                id: 'alpha-id', 
                type: 'dropdown', 
                options: [
                    { value: '', label: 'Select the alpha value' },
                    { value: '0', label: '0' },
                    { value: '1', label: '1' },
                    { value: '2', label: '2' },
                    { value: '3', label: '3' },
                    { value: '4', label: '4' },
                    { value: '5', label: '5' },
                    { value: '6', label: '6' },
                    { value: '7', label: '7' },

                    
                ]
            },
            
            { label: 'path Loss (PL)', id: 'pl-id-1', type: 'text' , validation: { required: true, type: 'int', customErrorMessage: 'path Loss (PL) must be a valid integer.' } },
            { label: 'Delta_TF', id: 'delta-tf-id', type: 'text' , validation: { required: true, type: 'int', customErrorMessage: 'Delta_TF must be a valid integer.' }  },
            { label: 'f(i)', id: 'f_i-id-1', type: 'text', validation: { required: true, type: 'int', customErrorMessage: 'f(i) must be a valid integer.' }  },
            { label: 'Pcmax', id: 'Pcmax-id-3', type: 'text', optional: true, validation: { type: 'int', customErrorMessage: 'Pcmax must be a valid integer.' } }

        ],

        4: [
            { label: 'log_m_pusch', id: 'log_m_pusch-id-2', type: 'text' , validation: { required: true, type: 'int', customErrorMessage: 'log_m_pusch must be a valid integer.' } },
            { label: 'Preamble_init_power', id: 'Preamble_init_power-id-2', type: 'text', validation: { required: true, type: 'int', customErrorMessage: 'Preamble_init_power must be a valid integer.' }  },
            { label: 'delta_msg3', id: 'delta_msg3-id', type: 'text', validation: { required: true, type: 'int', customErrorMessage: 'delta_msg3 must be a valid integer.' }  },
            { label: 'path Loss (PL)', id: 'pl-id-2', type: 'text', validation: { required: true, type: 'int', customErrorMessage: 'path Loss (PL) must be a valid integer.' }  },
            { label: 'f(0)', id: 'f_0-id', type: 'text', validation: { required: true, type: 'int', customErrorMessage: 'f(0) must be a valid integer.' }  }
           
        ],

        5: [
            { label: 'srsBW', id: 'srsBW-id', type: 'text', validation: { required: true, type: 'int', customErrorMessage: 'srsBW.' }  },

            {   
                label: 'delta_mcs_enabled? ', 
                id: 'delta_mcs_enabled-id', 
                type: 'dropdown', 
                options: [
                    { value: '', label: 'Select the delta_mcs_enabled' },
                    { value: '0', label: '0' },
                    { value: '1', label: '1' }, 
                ]
            },
            { label: 'srs_offset', id: 'srs_offset-id', type: 'text' , validation: { required: true, type: 'int', customErrorMessage: 'srs_offset must be a valid integer.' } },
            
            
            { label: 'P0_num_PUSCH', id: 'p0-num-pusch-id', type: 'text' , validation: { required: true, type: 'int', customErrorMessage: 'P0_num_PUSCH must be a valid integer.' } },
            { label: 'P0_UE_PUSCH', id: 'P0_UE_PUSCH-id', type: 'text' , validation: { required: true, type: 'int', customErrorMessage: 'P0_UE_PUSCH must be a valid integer.' } },
            {   
                label: 'Alpha value ', 
                id: 'alpha-id', 
                type: 'dropdown', 
                options: [
                    { value: '', label: 'Select the alpha value' },
                    { value: '0', label: '0' },
                    { value: '1', label: '1' },
                    { value: '2', label: '2' },
                    { value: '3', label: '3' },
                    { value: '4', label: '4' },
                    { value: '5', label: '5' },
                    { value: '6', label: '6' },
                    { value: '7', label: '7' },
                    
                ]
            },
            { label: 'Path Loss (PL)', id: 'pl-id-3', type: 'text' , validation: { required: true, type: 'int', customErrorMessage: 'Path Loss (PL) value must be a valid integer.' } },
            { label: 'f(i) value', id: 'f(i)-id', type: 'text', validation: { required: true, type: 'int', customErrorMessage: 'f(i) must be a valid integer.' }  },
            { label: 'Pcmax', id: 'pcmax-id-4', type: 'text',optional: true,  validation: { type: 'int', customErrorMessage: 'Pcmax must be a valid integer.' } }
           
        ],

        6: [
            { label: 'SFN Number', id: 'sfn-id', type: 'text' , validation: { required: true, type: 'int', customErrorMessage: 'SFN Number must be a valid integer.' } },
            { label: 'n_p or Npd value', id: 'np-id', type: 'text', validation: { required: true, type: 'int', customErrorMessage: 'n_p or Npd value must be a valid integer.' }  },
            { label: 'ns', id: 'ns-id', type: 'text', validation: { required: true, type: 'int', customErrorMessage: 'ns must be a valid integer.' }  },
            { label: 'n_offset_cqi', id: 'n_offset_cqi-id', type: 'text', validation: { required: true, type: 'int', customErrorMessage: 'n_offset_cqi must be a valid integer.' }  }

           
        ],
    },

        popupText: "parch_cal_pwr = Preamble_init_power + (preamble_transmission_counter-1) * power_ramping_step + pl  \n pucch_cal_pwr  = (p_zero_nom_pucch + p_ue_PUCCH_id) + pl + PucchFrm_h + delta_f + g_i \n pusch_cal_pwr = log_m_pusch + ( p0_num_pusch + p0_ue_pusch) + alpha_final * pl + delta_tf + f_i \n msg3_tx_pwr = log_m_pusch + (Preamble_init_power + delta_msg3) + pl + f_0 \n srs_power = P_SRS_Offset + log_m_srs + (p0_num_pusch  + P0_UE_PUSCH) + final_alpha * pl + f_i"
    },



'weighted-average': {
    title: 'WEIGHTED AVERAGE',
    domain: 'SAP',
    inputs: [
        {   
            label: 'Number of Subjects', 
            id: 'num-subjects', 
            type: 'dropdown', 
            options: [
                { value: '', label: 'Select' },
                { value: '1', label: '1 Subject' },
                { value: '2', label: '2 Subjects' },
                { value: '3', label: '3 Subjects' },
                { value: '4', label: '4 Subjects' }
            ]
        }
    ],
    subjectMappings: {
        1: [
            { label: 'Enter the Telugu Subject Marks', id: 'score-1', type: 'text' }
        ],
        2: [
            { label: 'Enter the Telugu Subject Marks', id: 'score-1', type: 'text' },
            { label: 'Enter the English Subject Marks (Optional)', id: 'score-2', type: 'text', optional: true }
        ],
        3: [
            { label: 'Enter the Social Subject Marks', id: 'score-1', type: 'text' },
            { 
                label: 'Enter the Science Subject Marks', 
                id: 'score-2', 
                type: 'radio-group', 
                options: [
                    { value: '10', label: '10' },
                    { value: '30', label: '30' },
                    { value: '40', label: '40' },
                    { value: '50', label: '50' },
                    { value: '100', label: '100' }
                ],
                groupName: 'scienceMarks'
            },
            { label: 'Enter the Physics Subject Marks', id: 'score-3', type: 'text' }
        ],
        4: [
            { label: 'Enter the Social Subject Marks', id: 'score-1', type: 'text' },
            { 
                label: 'Enter the Science Subject Marks', 
                id: 'score-2', 
                type: 'radio-group', 
                options: [
                    { value: '10', label: '10' },
                    { value: '30', label: '30' },
                    { value: '40', label: '40' },
                    { value: '50', label: '50' },
                    { value: '100', label: '100' }
                ],
                groupName: 'scienceMarks'
            },
            { label: 'Enter the Physics Subject Marks', id: 'score-3', type: 'text' },
            { 
                label: 'Enter the Maths Subject Marks', 
                id: 'score-4', 
                type: 'dropdown', 
                options: [
                    { value: '10', label: '10' },
                    { value: '150', label: '150' },
                    { value: '70', label: '70' },
                    { value: '100', label: '100' }
                ]
            }
        ]
    },
    popupText: 'Select the number of subjects and enter scores.\nLearn more: <a href="https://www.example.com/weighted-average" target="_blank">Weighted Average Guide</a>'
}


    // To add a new calculator, follow this template:
    // '[CALC_ID]': {
    //     title: 'Calculator Title',
    //     domain: 'Domain Name', // e.g., 'Telecom', 'Networking', 'SAP', 'Others'
    //     inputs: [
    //         { label: 'Input Label', id: 'input-id', type: 'text' },
    //         { label: 'Dropdown Label', id: 'dropdown-id', type: 'dropdown', options: [{ value: 'value1', label: 'Label1' }, ...] },
    //         { label: 'Checkbox Label', id: 'checkbox-id', type: 'checkbox', defaultChecked: false },
    //     ],
    //     popupText: 'Description of the calculator and how to use it.\nLearn more: <a href="link" target="_blank">Reference</a>'
    // },
    // Then, add the corresponding back-end logic in app.py under the /calculate route.
};

// Show the selected calculator in Box C and highlight in Box B






function showCalculator(calcId) {
    const calc = calculators[calcId];
    if (calc) {
        filterCalculators(calc.domain);
        const calcListItems = document.querySelectorAll('#calculator-list li');
        calcListItems.forEach(item => {
            item.classList.remove('selected');
            if (item.textContent === calc.title) {
                item.classList.add('selected');
            }
        });
        let formHtml = `<form id="${calcId}-form">`;
        calc.inputs.forEach(input => {
            if (input.hidden) return;
            if (input.type === 'text') {
                formHtml += `
                    <div class="form-field">
                        <input type="text" id="${input.id}" required placeholder=" ">
                        <label>${input.label}</label>
                    </div>
                `;
            } else if (input.type === 'dropdown') {
                let optionsHtml = input.options.map(option => 
                    `<option value="${option.value}">${option.label}</option>`
                ).join('');
                formHtml += `
                    <div class="form-field">
                        <select id="${input.id}" onchange="updateWeightedAverageFields('${calcId}')">
                            ${optionsHtml}
                        </select>
                        <label>${input.label}</label>
                    </div>
                `;
            } else if (input.type === 'checkbox') {
                formHtml += `
                    <div class="form-field checkbox-field">
                        <label>${input.label}</label>
                        <input type="checkbox" id="${input.id}" ${input.defaultChecked ? 'checked' : ''}>
                    </div>
                `;
            }
        });
        formHtml += `
                <button type="button" onclick="runCalculator('${calcId}')">Run</button>
            </form>
            <div id="output">Output: </div>
        `;
        document.getElementById('calculator-content').innerHTML = `
            <h2>${calc.title}</h2>
            ${formHtml}
        `;
        const sidebar = document.querySelector('.sidebar-container');
        sidebar.classList.remove('visible-mobile'); // Collapses the calculator dropdown
        const boxD = document.getElementById('box-d');
        console.log('Showing Box D - Calculator selected:', calcId);
        boxD.classList.add('visible');
        if (calcId === 'weighted-average') {
            updateWeightedAverageFields(calcId);
        }
        history.pushState({ calcId }, '', `/calculator/${calcId}`);
    }
}



// Update visibility of score fields based on the number of subjects selected
// Update visibility of score fields based on the selection
function updateWeightedAverageFields(calcId) {
    if (!(calcId in calculators) || !calculators[calcId].subjectMappings) return;

    const selectorId = calculators[calcId].inputs[0].id; // Assumes the first input is the dropdown
    const numItems = document.getElementById(selectorId)?.value;
    const calc = calculators[calcId];
    const form = document.getElementById(`${calcId}-form`);
    const outputDiv = document.getElementById('output');

    // Preserve existing output or reset if no prior output
    const outputText = outputDiv ? outputDiv.innerText : 'Output: ';

    // Reset form and re-render inputs
    let formHtml = `<form id="${calcId}-form">`;
    // Always include the selector dropdown
    calc.inputs.forEach(input => {
        if (input.type === 'dropdown') {
            let optionsHtml = input.options.map(option => 
                `<option value="${option.value}" ${option.value === numItems ? 'selected' : ''}>${option.label}</option>`
            ).join('');
            formHtml += `
                <div class="form-field">
                    <select id="${input.id}" onchange="updateWeightedAverageFields('${calcId}')">
                        ${optionsHtml}
                    </select>
                    <label>${input.label}</label>
                </div>
            `;
        }
    });

    // Add subject-specific fields based on selection, only if a valid number is selected
    if (numItems && calc.subjectMappings && calc.subjectMappings[parseInt(numItems)]) {
        calc.subjectMappings[parseInt(numItems)].forEach(input => {
            if (input.type === 'text') {
                const placeholder = input.optional ? '(Optional)' : '';
                formHtml += `
                    <div class="form-field">
                        <input type="text" id="${input.id}" ${input.optional ? '' : 'required'} placeholder="${placeholder}">
                        <label>${input.label}</label>
                    </div>
                `;
            } else if (input.type === 'dropdown') {
                let optionsHtml = input.options.map(option => 
                    `<option value="${option.value}">${option.label}</option>`
                ).join('');
                formHtml += `
                    <div class="form-field">
                        <select id="${input.id}" required>
                            ${optionsHtml}
                        </select>
                        <label>${input.label}</label>
                    </div>
                `;
            } else if (input.type === 'radio-group') {
                formHtml += `
                    <div class="form-field">
                        <label>${input.label}</label>
                        ${input.options.map(option => `
                            <div class="radio-option">
                                <input type="radio" id="${input.id}-${option.value}" name="${input.groupName}" value="${option.value}">
                                <label for="${input.id}-${option.value}">${option.label}</label>
                            </div>
                        `).join('')}
                    </div>
                `;
            }
        });
    }

    formHtml += `
            <button type="button" onclick="runCalculator('${calcId}')">Run</button>
        </form>
        <div id="output">${outputText}</div>
    `;
    document.getElementById('calculator-content').innerHTML = `
        <h2>${calc.title}</h2>
        ${formHtml}
    `;
}



function validateInputs(calcId) {
    const calc = calculators[calcId];
    let inputsToValidate = [];
    let numItems = null;

    // Determine inputs to validate based on calculator type
    if (calc.subjectMappings) {
        const selectorId = calc.inputs[0].id;
        numItems = document.getElementById(selectorId)?.value;
        if (!numItems || numItems === '') {
            return [calc.inputs[0].validation.customErrorMessage || 'Please select an option.'];
        }
        const numItemsInt = parseInt(numItems);
        inputsToValidate = calc.subjectMappings[numItemsInt] || [];
    } else {
        inputsToValidate = calc.inputs.filter(input => !input.hidden);
    }

    const validationErrors = [];
    inputsToValidate.forEach(input => {
        const element = document.getElementById(input.id);
        if (!element) return;

        const validation = input.validation || { required: true, type: 'string', customErrorMessage: `${input.label} is required.` };
        const isRequired = input.optional === true ? false : validation.required;
        let value = input.type === 'checkbox' ? element.checked : element.value.trim(); // Trim spaces here

        // Check required fields
        if (isRequired && !value) {
            validationErrors.push(validation.customErrorMessage || `${input.label} is required.`);
            return;
        }

        // Validate type if value exists
        if (value) {
            switch (validation.type) {
                case 'int':
                    if (isNaN(parseInt(value)) || !/^-?\d+$/.test(value)) {
                        validationErrors.push(validation.customErrorMessage || `${input.label} must be a valid integer.`);
                    }
                    break;
                case 'float':
                    if (isNaN(parseFloat(value)) || !/^-?\d*\.?\d+$/.test(value)) {
                        validationErrors.push(validation.customErrorMessage || `${input.label} must be a valid number.`);
                    }
                    break;
                case 'number': // New case for int or float
                    if (isNaN(parseFloat(value)) || !/^-?\d*\.?\d+$/.test(value)) {
                        validationErrors.push(validation.customErrorMessage || `${input.label} must be a valid number (integer or decimal).`);
                    }
                    break;
                case 'string':
                    if (typeof value !== 'string' || value.trim() === '') {
                        validationErrors.push(validation.customErrorMessage || `${input.label} must be a valid string.`);
                    }
                    break;
                default:
                    break;
            }
        }

        // Special handling for radio-group
        if (input.type === 'radio-group' && isRequired && !document.querySelector(`input[name="${input.groupName}"]:checked`)) {
            validationErrors.push(validation.customErrorMessage || `${input.label} is required.`);
        }
    });

    return validationErrors;
}
// Function to show modal

function showModal(message) {
    const modal = document.getElementById('errorModal');
    const modalMessage = document.getElementById('modalMessage');
    
    // If message is a string with newlines, split into array and create a list
    if (typeof message === 'string') {
        const errors = message.split('\n').filter(error => error.trim() !== '');
        let htmlContent = '<ul>';
        errors.forEach(error => {
            htmlContent += `<li>${error}</li>`;
        });
        htmlContent += '</ul>';
        modalMessage.innerHTML = htmlContent; // Use innerHTML for list rendering
    } else {
        modalMessage.textContent = message; // Fallback for single message
    }
    
    modal.style.display = 'block';

    // Close modal when clicking the close button
    document.getElementById('closeModal').onclick = function() {
        modal.style.display = 'none';
    };

    // Close modal when clicking outside
    window.onclick = function(event) {
        if (event.target == modal) {
            modal.style.display = 'none';
        }
    };
}