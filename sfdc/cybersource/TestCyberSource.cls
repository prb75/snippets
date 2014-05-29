public with sharing class TestCyberSource {
    private static final String HMAC_SHA256 = 'HmacSHA256';

    //these values come from the cybersource business center in tools & settings / secure acceptance / profiles / general settings
    public static final String PROFILE_ID = '<PROFILE_ID>';
    
    //these values come from the cybersource business center in tools & settings / secure acceptance / profiles / privacy
    public static final String ACCESS_KEY = '<ACCESS_KEY>';
    public static final String SECRET_KEY = '<SECRET_KEY>';

    public static final String SIGNED_FIELD_NAMES = 'access_key,profile_id,transaction_uuid,signed_field_names,'+
                                                   'unsigned_field_names,signed_date_time,locale,'+
                                                   'transaction_type,reference_number,amount,currency,'+
                                                   'payment_method,bill_to_forename,bill_to_surname,'+
                                                   'bill_to_email,bill_to_phone,bill_to_address_line1,'+
                                                   'bill_to_address_city,bill_to_address_state,'+
                                                   'bill_to_address_country,bill_to_address_postal_code';
    
    public static final String UNSIGNED_FIELD_NAMES = 'card_type,card_number,card_expiry_date';
    public static final String TRANS_UUID = GuidGenerator.generateGUID();
    public static final String SIGNED_DT = System.Now().format('yyyy-MM-dd\'T\'HH:mm:ss\'Z\'','GMT');

    public static final String LOCALE = 'en';

    public static final Map<String,String> signedValueMap = null;
    static { 
        signedValueMap = new Map<String,String>();
        signedValueMap.put('access_key',ACCESS_KEY);
        signedValueMap.put('profile_id',PROFILE_ID);
        signedValueMap.put('transaction_uuid',TRANS_UUID);
        signedValueMap.put('signed_field_names',SIGNED_FIELD_NAMES);
        signedValueMap.put('unsigned_field_names',UNSIGNED_FIELD_NAMES);
        signedValueMap.put('signed_date_time',SIGNED_DT);
        signedValueMap.put('locale',LOCALE);
        signedValueMap.put('transaction_type','authorization');   
        signedValueMap.put('reference_number',SIGNED_DT); 
        signedValueMap.put('amount','100.00'); 
        signedValueMap.put('currency','USD'); 
        signedValueMap.put('payment_method','card'); 
        signedValueMap.put('bill_to_forename','Fido'); 
        signedValueMap.put('bill_to_surname','Watkins'); 
        signedValueMap.put('bill_to_email','fido@bs.com'); 
        signedValueMap.put('bill_to_phone','5555555555'); 
        signedValueMap.put('bill_to_address_line1','999 Main St'); 
        signedValueMap.put('bill_to_address_city','Pittsburgh');   
        signedValueMap.put('bill_to_address_state','PA'); 
        signedValueMap.put('bill_to_address_country','US'); 
        signedValueMap.put('bill_to_address_postal_code','15233');     
    }                                        




    public static void testSilentOrder() {    
        List<String> signedFields = new List<String>();
        String formPostValues = '';
        for (String fieldName : SIGNED_FIELD_NAMES.split(',')) {
            signedFields.add(fieldName + '=' + signedValueMap.get(fieldName)); 
            formPostValues+=fieldName + '=' + signedValueMap.get(fieldName) + '&'; 
        }
        String signedFieldsStr = commaSeparate(signedFields);
        system.debug('PMN: cybersource signedFieldsStr = '+signedFieldsStr);

        String signature = generateSignature(signedFieldsStr, SECRET_KEY);
        system.debug('PMN: cybersource signature = '+signature);

        String payload = generatePayload(formPostValues,signature);   
        system.debug('PMN: cybersource payload = '+payload.replaceAll('\n','|'));

        HttpRequest req = new HttpRequest();
        req.setEndpoint('https://testsecureacceptance.cybersource.com/silent/pay');        
        req.setMethod('POST');
        req.setBody(payload); 

        Http h = new Http();

        try{
           HttpResponse res = h.send(req);
           String responseStr = res.getBody();

           system.debug('PMN: cybersource responseStr = '+responseStr); 

        } catch(Exception e){
           throw e;
        }



    }    

    private static String generatePayload(String formPostValues, String signature) {
        String payload = formPostValues;
        payload+='signature='+signature+'&';
        payload+='card_type=001&';
        payload+='card_number=4242424242424242&';
        payload+='card_expiry_date=11-2020';    

        return payload;

    }


    //======================UTILITY METHODS=========================
            
    public static String generateSignature(String saltValue, String secretKeyValue) {
        String algorithmName = HMAC_SHA256;
        Blob hmacData = Crypto.generateMac(algorithmName, Blob.valueOf(saltValue), 
                                           Blob.valueOf(secretKeyValue));
        String encodedSign = EncodingUtil.base64Encode(hmacData);
        return EncodingUtil.urlEncode(encodedSign, 'UTF-8');
    }

    public static String commaSeparate(List<String> dataToSign) {
        Iterator<String> dtsIterator = dataToSign.iterator();
        String csv = '';
        while(dtsIterator.hasNext()) {
            csv += dtsIterator.next();
            if (dtsIterator.hasNext())
                csv += ',';
        }
        return csv;
    }




}