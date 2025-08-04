<?php

if (!defined('ABSPATH')) die('No direct access.');

class WC_VAT_Compliance_Order_Export {
	
	/**
	 * Get the order data. The output is likely to be around 50-100KB of data.
	 *
	 * @param Integer|Object $order
	 * @param Array			 $options - supported keys are:
	 * 	(boolean) 'clean_pii'			- default true. N.B. Addresses are already cleansed. Currently this purges the IP address. This cannot guarantee that the export contains no PII; for example, the order meta or order notes may contain it.
	 *  (boolean) 'include_all_meta'    - default true
	 *  (boolean) 'include_order_notes' - default true
	 * @return Array|WP_Error
	 */
	public static function get_export_data($order, $options = array()) {
		
		global $wpdb, $table_prefix;
		
		$options = wp_parse_args($options, array('clean_pii' => true, 'include_all_meta' => true, 'include_order_notes' => true));
		
		if (is_int($order)) $order = wc_get_order($order);
		
		if (!is_object($order)) return new WP_Error('order_not_found', 'No order could be found from the passed order parameter');
		
		include ABSPATH.WPINC.'/version.php';
		
		$compliance = WooCommerce_EU_VAT_Compliance();
		
		$base_data = self::get_base_data($order);
		
		foreach (array('billing', 'shipping') as $address_type_key) {
			foreach (array_keys($base_data[$address_type_key]) as $address_key) {
				if (!in_array($address_key, array('company', 'city', 'state', 'country'))) {
					unset($base_data[$address_type_key][$address_key]);
				}
			}
		}
		
		if ($options['clean_pii'] && !empty($base_data['customer_ip_address'])) $base_data['customer_ip_address'] = substr($base_data['customer_ip_address'], 0, 5).' ...';
		
		$order_metadata_kv = self::get_meta_data_kv($order);
		
		$hpos_enabled = $compliance->woocommerce_custom_order_tables_enabled();
		
		$db_raw = array();
		if ($hpos_enabled) {
			// This is useful because potentially a field like tax_amount which is calculated from other data may be in an inconsistent state, which cannot be detected without the raw DB data
			$db_raw['wc_orders'] = $wpdb->get_results($wpdb->prepare("SELECT * FROM {$table_prefix}wc_orders WHERE id=%d", $order->get_id()), ARRAY_A);
		}
		
		$db_raw['woocommerce_order_items'] = self::get_db_order_items($order);
		
		// The table wc_order_tax_lookup is only used at the time of writing (April 2025) for WooCommerce's reports. i.e. It is not used in the back-end order screen, and the VAT plugin does not use it.
		$db_raw['wc_order_tax_lookup'] = $wpdb->get_results($wpdb->prepare("SELECT * FROM {$table_prefix}wc_order_tax_lookup WHERE order_id=%d", $order->get_id()), ARRAY_A);
		
		$locations = $wpdb->get_results("SELECT * FROM {$table_prefix}woocommerce_tax_rate_locations", OBJECT);
		foreach ($locations as $location) {
			$location_id = $location->location_id;
			unset($location->location_id);
			$db_raw['woocommerce_tax_rate_locations'][$location_id] = (array) $location;
		}
		
		$tax_rates = $wpdb->get_results("SELECT * FROM {$table_prefix}woocommerce_tax_rates", OBJECT);
		foreach ($tax_rates as $tax_rate) {
			$tax_rate_id = $tax_rate->tax_rate_id;
			unset($tax_rate->tax_rate_id);
			$db_raw['woocommerce_tax_rates'][$tax_rate_id] = (array) $tax_rate;
		}
		
		
		// The table wc_tax_rate_classes is not useful: it translates from human-readable names to slugs; but the human-readable names are not used as part of any order data and are usually essentially inferrable anyway
		
		$order_refunds = $order->get_refunds();
		$refunds = array();
		foreach($order_refunds as $order_refund) {
			$refund_base_data = self::get_base_data($order_refund);
			$refund_id = $order_refund->get_id();
			$refunds[$refund_id] = array(
				'base_data_api' => $refund_base_data,
			);
			if ($options['include_all_meta']) {
				$refunds[$refund_id]['meta'] = self::get_meta_data_kv($order_refund);
			}
			$refunds[$refund_id]['db_raw']['woocommerce_order_items'] = self::get_db_order_items($order_refund);
			
			if ($hpos_enabled) {
				$refunds[$refund_id]['db_raw']['wc_orders'] = $wpdb->get_results($wpdb->prepare("SELECT * FROM {$table_prefix}wc_orders WHERE id=%d", $refund_id), ARRAY_A);
			}
			
		}
		
		$results = array(
			'export_environment' => array(
				'versions' => array(
					'wordpress' => $wp_version,
					'woocommerce' => WC_VERSION,
					'vat_compliance' => $compliance->get_version(),
				),
				'features' => array(
					'hpos_enabled' => $hpos_enabled,
					'checkout_page_using_shortcode' => $compliance->checkout_page_uses_shortcode(),
					'cart_page_using_shortcode' => $compliance->cart_page_uses_shortcode(),
				),
				'export_options' => $options,
				'date_gmt' => gmdate('Y-m-d H:i:s'),
			),
			'order_info' => array(
				$order->get_id() => array(
					'base_data_api' => $base_data,
					'meta' => array(
						'vat' => array(
							'vat_compliance_vat_paid' => $order_metadata_kv['vat_compliance_vat_paid'] ?? null,
							'vat_compliance_country_info' => $order_metadata_kv['vat_compliance_country_info'] ?? null,
							'wceuvat_conversion_rates' => $order_metadata_kv['wceuvat_conversion_rates'] ?? null,
							'is_vat_exempt' => $order_metadata_kv['is_vat_exempt'] ?? null,
							'VAT Number' => $order_metadata_kv['VAT Number'] ?? null,
							'Valid VAT Number' => $order_metadata_kv['Valid VAT Number'] ?? null,
							'VAT number validated' => $order_metadata_kv['VAT number validated'] ?? null,
							'vat_lookup_response' => $order_metadata_kv['vat_lookup_response'] ?? null,
							'VIES Response' => $order_metadata_kv['VIES Response'] ?? null,
							'_vat_shop_order_meta_processed' => $order_metadata_kv['_vat_shop_order_meta_processed'] ?? null,
							'order_time_order_number' => $order_metadata_kv['order_time_order_number'] ?? null,
						),
					),
					// The above data is fetched from the WooCommerce APIs; but if the database has inconsistencies, then that won't be visible in that
					'db_raw' => $db_raw,
					'refunds' => $refunds,
				),
			),
		);
		
		if ($options['include_all_meta']) $results['order_info']['meta']['all'] = $order_metadata_kv;
		
		if ($options['include_order_notes']) {
			$order_notes = array();
			$notes = wc_get_order_notes(['order_id' => $order->get_id()]);
			foreach ($notes as $note) {
				$results['order_info']['notes'][$note->id] = array(
					'created_gmt' => $note->date_created->date('Y-m-d H:i:s'),
					'added_by' => $note->added_by,
					'customer_note' => $note->customer_note,
					'content' => $note->content,
				);
			}
		}
		
		return $results;
		
	}
	
	/**
	 * Get the base data for an order, replacing any WC_DateTime objects
	 *
	 * @param WC_Order|WC_Order_Refund $order
	 *
	 * @return Array
	 */
	private static function get_base_data($order) {
		$base_data = $order->get_base_data();
		foreach ($base_data as $key => $value) {
			if (is_object($value) && is_a($value, 'WC_DateTime')) {
				$base_data[$key] = $value->date('Y-m-d H:i:s');
			}
		}
		return $base_data;
	}
	
	/**
	 * Get the order meta-data for an order, in key-value form
	 *
	 * @param WC_Order|WC_Order_Refund $order
	 *
	 * @return Array
	 */
	private static function get_meta_data_kv($order) {
		$order_metadata = $order->get_meta_data();
		$order_metadata_kv = array();
		
		foreach ($order_metadata as $meta_item) {
			$order_metadata_kv[$meta_item->key] = $meta_item->value;
		}
		return $order_metadata_kv;
	}
	
	/**
	 * Get the order items and item-meta, in a single array (where keys are database IDs)
	 *
	 * @param WC_Order|WC_Order_Refund $order
	 *
	 * @return Array
	 */
	private static function get_db_order_items($order) {
		
		global $wpdb, $table_prefix;
		
		$woocommerce_order_items = array();
		
		$order_items = $wpdb->get_results($wpdb->prepare("SELECT order_item_id AS id, order_item_name AS name, order_item_type AS type FROM {$table_prefix}woocommerce_order_items WHERE order_id=%d", $order->get_id()), OBJECT);
		
		foreach ($order_items as $order_item) {
			$woocommerce_order_items[$order_item->id] = array('name' => $order_item->name, 'type' => $order_item->type);
		}
		
		$order_item_ids = array();
		foreach ($order_items as $order_item) {
			$order_item_ids[] = $order_item->id;
		}
		
		$order_item_ids = array_unique($order_item_ids);
		
		if (!empty($order_item_ids)) {
			$order_itemmeta = $wpdb->get_results("SELECT meta_id AS id, order_item_id AS item_id, meta_key, meta_value FROM {$table_prefix}woocommerce_order_itemmeta WHERE order_item_id IN (".implode(',', array_map('absint', $order_item_ids)).')', OBJECT);
		}
		
		foreach ($order_itemmeta as $itemmeta) {
			if ('_line_tax_data' === $itemmeta->meta_key && is_serialized($itemmeta->meta_value)) $itemmeta->meta_value = unserialize($itemmeta->meta_value, array('allowed_classes' => false));
			$woocommerce_order_items[$itemmeta->item_id]['meta'][$itemmeta->id] = array('key' => $itemmeta->meta_key, 'value' => $itemmeta->meta_value);
		}
		
		return $woocommerce_order_items;
		
	}
	
}
