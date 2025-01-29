$(document).ready(function () {
    let loginData = {};

    $(document).on("totp:required", function (event, data) {
        loginData = data;
        $("#totp-modal").removeClass("hidden");
    });

    $("#submit-totp").on("click", function () {
        const totpCode = $("#totp-code").val();

        loginData.totp_code = totpCode;
        const apiEndpoint = loginData.endpoint;

        $.ajax({
            url: apiEndpoint,
            method: "POST",
            contentType: "application/json",
            data: JSON.stringify(loginData),
            success: function (response) {
                $("#response-message")
                    .text(response.message)
                    .addClass("text-green-500");

                window.location.href = "/";
            },
            error: function (xhr) {
                const errorMessage =
                    xhr.responseJSON?.message || "An error occurred";
                $("#response-message")
                    .text(errorMessage)
                    .addClass("text-red-500");
            },
        });

        $("#totp-modal").addClass("hidden");
    });

    $("#cancel-totp").on("click", function () {
        $("#totp-modal").addClass("hidden");
    });
});
