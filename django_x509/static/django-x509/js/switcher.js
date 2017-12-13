(function($){
    // function for operation_type switcher
    var filter_div = function(operation_type){
        // define fields for each operation_type
        var import_fields = $('.form-row:not(.field-certificate, .field-operation_type, .field-private_key, .field-name, .field-ca)'),
        new_fields = $('.form-row:not(.field-certificate, .field-private_key)'),
        default_fields = $('.form-row:not(.field-operation_type)'),
        all_fields = $('.form-row');
        if(operation_type === '-----'){
            all_fields.show()
            default_fields.hide()
        }
        if(operation_type === 'Create new'){
            all_fields.hide()
            new_fields.show()
        }
        if(operation_type === 'Import Existing'){
            all_fields.show()
            import_fields.hide()
        }
    }
    $(document).ready(function(){
        // dont hide if edit cert
        var path = window.location.pathname
        if(path.indexOf("change") === -1){
            // if field is set
            if ($(".field operation_type" != "-----")){
                filter_div($(".field-operation_type").find(":selected").text())
            } else {
                // filter default if field is not set
                filter_div('-----')
            }
            $(".field-operation_type").on('change', function(){
                switcher = $(".field-operation_type").find(":selected").text()
                filter_div(switcher)
            })
        } else {
            $(".field-operation_type").hide()
        }
    })
})(django.jQuery);
