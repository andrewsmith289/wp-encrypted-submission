<?php

/**
 * Strain Manager Common Utility Functions
 *
 * This class defines all utility functions that are shared between class-strain-manager-admin and
 * class-strain-manager-public, as well as file encryption functionality
 *
 * @since      1.1.0
 * @package    Product_Manager_Utils
 * @subpackage Product_Manager/includes
 * @author     ---------------
 */
class Product_Manager_Utils {

    /**
     * Creates a new subscription to the SendGrid newsletter
     * @param $email
     */
    public static function create_newsletter_sub( $email ) {

        if ( ! $email ) return;
        $email = sanitize_email( $email );

        if ( !class_exists( 'SendGrid\Email' ) ) {
            require PRODUCT_MANAGER_PATH . 'vendor/autoload.php';
        }

        //API credentials
        require PRODUCT_MANAGER_PATH . 'sendgrid.php';
        $sg = new \SendGrid(SENDGRID_API_KEY);

        ///////////////////////////////////
        // API Create New Recipient      //
        ///////////////////////////////////
        $request_body = json_decode( '[{
          "email": "' . $email . '"
        }]' );
        $response = $sg->client->contactdb()->recipients()->post( $request_body );

        if ( 201 !== $response->statusCode() ) {
            error_log( "Error adding new recipient to SendGrid contacts, response was: " . $response->body() );
            error_log( "Request:" );
            error_log( print_r( $request_body, true ) );
            return;
        }

        $response_data = json_decode( $response->body(), true );
        $new_id = $response_data['persisted_recipients'][0];

        //Existing recipient
        if ( ! $response_data["error_count"] && ! $new_id ) {
            error_log( "Error adding new recipient to SendGrid contacts. The contact already exists.");
            return;
        }

        //////////////////////////////////
        // API Add a Recipient to List  //
        //////////////////////////////////
        $list_id = SENDGRID_NEWSLETTER_LIST_ID;
        $response = $sg->client->contactdb()->lists()->_( $list_id )->recipients()->_( $new_id )->post();
        if ( 201 !== $response->statusCode() ) {
            error_log( "Error adding Recipient to SendGrid list " . $list_id . ", response was: "
                . $response->body() );
            error_log( "Recipient ID: " . $new_id );
            error_log( "Original request:" );
            error_log( print_r( $request_body, true ) );
            return;
        }

    }

    /**
     * Seals a file with a public key
     * @param $data_path
     * @param $output_path
     * @param $pub_key
     * @param bool $delete_original
     * @return bool
     */
    static function seal_file($data_path, $output_path, $pub_key, $delete_original = false ) {

        if ( ! $data_path || ! $output_path || ! $pub_key ) {
            error_log( 'seal_file: missing parameters.' );
            return false;
        }

        $data_handle = fopen( $data_path, 'rb' );
        $data =  fread( $data_handle, filesize( $data_path) );

        $sealed_data = NULL;
        $envelope_key = NULL;
        $pub_key = file_get_contents( $pub_key );
        $iv = openssl_random_pseudo_bytes(16);

        if ( openssl_seal( $data, $sealed_data, $envelope_key, array( $pub_key ), "AES256", $iv ) ) {
            //Write out the env + iv
            self::write_env_with_iv( $output_path, $envelope_key[0], $iv );
            //Write sealed data
            file_put_contents( $output_path . '.sealed', $sealed_data );

            if ( $delete_original ) {
                //delete unencrypted original
            }

            return true;
        }

        return false;
    }

    /**
     * Writes a file containing a concatenated envelope key and iv
     * @param $output_path
     * @param $envelope
     * @param $iv
     */
    static function write_env_with_iv( $output_path, $envelope, $iv ) {

        //Write IV to key envelope
        file_put_contents( $output_path . '.env', $iv );

        //Followed by env key
        $handle=fopen( $output_path . '.env', "a+" );
        fwrite( $handle, $envelope );
        fclose( $handle );
    }

    /**
     * Unencrypts and returns the data from a file
     * @param $file_path
     * @param $priv_key
     * @return bool|null
     */
    static function get_unsealed_file_data( $file_path, $priv_key ) {

        if ( ! $file_path  || ! $priv_key ) {
            error_log( "unseal_file: a file_path and private key must be provided." );
            return false;
        }

        if ( ! file_exists( rtrim( $file_path, '/' ) ) ) {
            error_log( "unseal_file: the provided file doesn't exist: $file_path");
            return false;
        }

        $file_path = rtrim( $file_path, DIRECTORY_SEPARATOR );
        $sealed_data = file_get_contents( $file_path . '.sealed' );

        $open_data = null;
        $env_key = self::extract_env_from_file( $file_path . '.env' );
        $priv_key = self::process_priv_key( $priv_key );
        $iv = self::extract_iv_from_file( $file_path . '.env' );

        openssl_open( $sealed_data, $open_data, $env_key, $priv_key , "AES256", $iv );

        return $open_data;
    }

    /**
     * Performs any necessary processing on the given private key
     * @param $priv_key
     * @return mixed
     */
    static function process_priv_key( $priv_key ) {

        //create a temp file to write the priv_key to (so we can later provide a handle)
//        $tempPemFile = tmpfile();
//        fwrite($tempPemFile, $priv_key);
//        $tempPemPath = stream_get_meta_data($tempPemFile);
//        $tempPemPath = $tempPemPath['uri'];

        return str_replace( '\r\n', "\r\n", $priv_key ); //replace newlines escape chars with actual new lines
    }

    /**
     * Extracts and returns a iv of a given length from a combined ik + envelope file
     * @param $file_path
     * @param int $iv_length
     * @return string
     */
    static function extract_iv_from_file( $file_path, $iv_length = 16 ) {

        $handle = fopen( $file_path , "r" );
        $iv = fread( $handle, $iv_length );
        fclose( $handle );

        return $iv;
    }

    /**
     * Extracts and returns a key envelope from a combined ik + envelope combined file
     * @param $file_path
     * @param int $iv_length
     * @return string
     */
    static function extract_env_from_file( $file_path, $iv_length = 16 ) {

        $handle = fopen( $file_path , "r" );
        fseek( $handle, $iv_length );
        $env_data = fread( $handle, filesize( $file_path ) );
        fclose( $handle );

        return $env_data;
    }

}