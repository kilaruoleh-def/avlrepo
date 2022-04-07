function tableBuilder(table, options, fieldSearch) {
    var thString = "";
    var headers = $.map($('#' + table + ' th'), function (el) {
        return [$(el).text()]
    });
    for (var h in headers) {
        if (headers[h] == " ") {
            headers[h] = "";
        }
        if (thString == "") {
            thString = "<th class='filterHeader'>" + headers[h] + "</th>";
        } else {
            thString = thString + "<th class='filterHeader'>" + headers[h] + "</th>";
        }
    }
    if (fieldSearch == 'yes') {
        $("#" + table + " thead").append("<tr id='filterrow'>" + thString + "</tr>");

        $('#' + table + ' thead tr#filterrow th').each(function () {
            var title = $('#' + table + ' thead th').eq($(this).index()).text();
            var titleStr = String(title);
            if (titleStr == "ID") {
                $(this).html('<input class="hide" type="text" onclick="stopPropagation(event);" placeholder="Search" title="Search ' + titleStr + ' field" />');
            } else if (titleStr == " ") {
                $(this).html('<input style="visibility:hidden" type="text" onclick="stopPropagation(event);"/>');
            } else {
                $(this).html( '<input class="fieldSearch" type="text" onclick="stopPropagation(event);" placeholder="Search" title="Search ' + titleStr + ' field" />');
            }
        });
    }

    var datatable = $('#' + table).DataTable(options);

    $("thead input").on('keyup change', function () {
        datatable
            .column($(this).parent().index() + ':visible')
            .search(this.value)
            .draw();
    });
    $(".dataTables_filter").css('display', 'none');

    return datatable;
}
function stopPropagation(evt) {
    if (evt.stopPropagation !== undefined) {
        evt.stopPropagation();
    } else {
        evt.cancelBubble = true;
    }
}