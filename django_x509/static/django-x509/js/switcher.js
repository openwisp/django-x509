django.jQuery(function ($) {
    'use strict';
    var operationType = $(".field-operation_type select");
    // enable switcher only in add forms
    if ($('form .deletelink-box').length > 0) {
        operationType.hide();
        return;
    }
    // function for operation_type switcher
    var showFields = function () {
        // define fields for each operation
        var importFields = $('.form-row:not(.field-certificate, .field-operation_type, ' +
                          '.field-private_key, .field-name, .field-ca)'),
            newFields = $('.form-row:not(.field-certificate, .field-private_key)'),
            defaultFields = $('.form-row:not(.field-operation_type)'),
            allFields = $('.form-row'),
            value = operationType.val();
        if (!value) {
            allFields.show();
            defaultFields.hide();
        }
        if (value === 'new') {
            allFields.hide();
            newFields.show();
        }
        if (value === 'import') {
            allFields.show();
            importFields.hide();
        }
    };
    showFields();
    operationType.on('change', function (e) {
        showFields();
    });
});
