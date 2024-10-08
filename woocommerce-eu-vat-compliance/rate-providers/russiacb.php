<?php

if (!defined('WC_VAT_COMPLIANCE_DIR')) die('No direct access.');

// Purpose: Official Central Bank of the Russian Federation exchange rates: https://www.cbr.ru/eng/

// Methods: info(), convert($from_currency, $to_currency, $amount, $the_time = false), settings_fields(), test()

if (!class_exists('WC_VAT_Compliance_Rate_Provider_base_xml')) require_once(WC_VAT_COMPLIANCE_DIR.'/rate-providers/base-xml.php');

// Conditional execution to deal with bugs on some old PHP versions with classes that extend classes not known until execution time
if (1==1):
class WC_VAT_Compliance_Rate_Provider_russiacb extends WC_VAT_Compliance_Rate_Provider_base_xml {

	protected $getbase = 'https://www.cbr.ru/scripts/XML_daily.asp';

	protected $rate_base_currency = 'RUB';

	# The rates change daily.
	protected $force_refresh_rates_every = 21600;

	protected $key = 'russiacb';

	public function info() {
		return array(
			'title' => __('The Central Bank of the Russian Federation', 'woocommerce-eu-vat-compliance'),
			'url' => 'https://www.cbr.ru',
			'description' => __('Official exchange rates from the Bank of Russia.', 'woocommerce-eu-vat-compliance')
		);
	}

	public function get_current_conversion_rate_from_time($currency, $the_time = false) {

		$parsed = $this->populate_rates_parsed_xml($the_time);
		if (empty($parsed)) return false;

		if (is_object($parsed)) {
			foreach ($parsed as $cur){
				if (isset($cur->CharCode) && $currency == strtoupper($cur->CharCode) && isset($cur->Value)) {
					$rate = (float)str_replace(',', '', $cur->Value);
					return (0 == $rate) ? false : 1/$rate;
				}
			} 
		}
		return false;
	}

}
endif;
