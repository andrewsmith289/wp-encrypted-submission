<?php

/////////////////////////////////////////////////////////////////////////////////////
// Provides transparent decryption for files forwarded as a url string via htaccess
// ******store 2017
/////////////////////////////////////////////////////////////////////////////////////


$headers = apache_request_headers();

if ( ! $headers['s5'] ) {
    echo "You're doing it wrong...";
    die();
}

if ( ! class_exists( 'Product_Manager_Utils' ) ) {
    require '/var/www/html/wp-content/plugins/product-manager/includes/class-product-manager-utils.php';
}

if ( ! defined( 'REDACTED_PUB_KEY_NAME') ) {
    require '/var/www/html/wp-content/plugins/product-manager/crypt.php';
}

$priv_key = $headers['s5'];
$target_path = get_path_from_request( $_SERVER['REQUEST_URI']);
$unsealed_data = Product_Manager_Utils::get_unsealed_file_data( $target_path, $priv_key );

if ( $unsealed_data ) {
    set_header_content_type( basename( $target_path ) );
    header('Content-Length: ' . strlen( $unsealed_data ));
    echo $unsealed_data;
} else {
    echo 'Sorry, unable to decrypt the file.';
}

die();

/**
 * Returns the target path to decrypt from a htaccess forwarded url
 * @param $request_uri
 * @return string
 */
function get_path_from_request( $request_uri ) {

    $target_path = explode( '?/',  $request_uri )[1];
    $target_path = filter_var( $target_path, FILTER_SANITIZE_URL );
    return UM_BASE_DIR . $target_path;
}

/**
 * Sets the content type header based upon the provided file path's extension
 * @param $file_name
 */
function set_header_content_type( $file_name ) {

    $ext = explode( '.', $file_name )[1];

    $ext_to_mime = Array(
       // "gif" => "image/gif",
        "jpg" => "image/jpeg",
        "jpeg" => "image/jpeg",
        "png" => "image/png",
        "bmp" => "image/bmp",
    );

    header( 'Content-type: ' . $ext_to_mime[ $ext ] );
}