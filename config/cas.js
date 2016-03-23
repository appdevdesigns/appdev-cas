/**
 * CAS settings
 */

module.exports.cas = {

	/*
	 *  baseURL: the url to your CAS server.  
	 */ 
    baseURL: 'https://signin.example.com:443/cas',

    /*
     *  pgtURL: the url to your PGT server.
     *
     *  if you don't support Proxy Connections then just leave this 'undefined'
     */
    pgtURL : undefined,


    /*
     * guidKey: the object key that holds the global unique ID for 
     * this CAS user.
     */
    guidKey: 'guidKey'

};