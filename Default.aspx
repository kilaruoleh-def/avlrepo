<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Default.aspx.cs" Inherits="AVLReport.Default" %>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <title>AVL Vehicle Reporting Information</title>
    <link rel="Stylesheet" type="text/css" href="./css/layout-2col-left.css" />
    <link rel="Stylesheet" type="text/css" href="./css/AVLReport.css" />
    <link rel="stylesheet" type="text/css" href="css/dataTables_buttons.min.css"/>
    <link rel="stylesheet" type="text/css" href="./css/dataTables.min.css" />
    <script type="text/javascript" src="./js/jquery-3.3.1.min.js"></script>
    <script type="text/javascript" src="./js/dataTables.min.js"></script>
    <script type="text/javascript" src="./js/dataTables_print.js"></script>
    <script type="text/javascript" src="./js/html5_buttons.min.js"></script>
    <script type="text/javascript" src="./js/dataTables_buttons.min.js"></script>
    <script type="text/javascript" src="./js/jszip.min.js"></script>
    <script type="text/javascript" src="./js/dataTableBuilder.js"></script>
</head>
<body>
<form runat="server">
    <asp:ScriptManager ID="ScriptManager" runat="server"></asp:ScriptManager>
	<div id="rightcontainer-wrapper">
		<div id="rightcontainer">
		    <p class="Title">Automatic Vehicle Location (AVL) - Information</p>
            <p>This page displays a list of all Schedule B vehicles that provide AVL information.  Information provided includes location, connection type, and date/time of last report.</p>
		    <p id="dateField" runat="server"></p>
            <div style="margin-bottom: 10px;">
                <label class="eccLabel">Select an ECC: </label>
                <asp:DropDownList class="ddl" id="eccDdl" runat="server" autopostback="true">
                    <asp:ListItem value="ALL" Text="Show All"/>
                </asp:DropDownList>
                <asp:Button runat="server" id="refreshBtn" autopostback="true" Text="Refresh Data" class="btn"/>
            </div>
            <asp:UpdatePanel runat="server" UpdateMode="Always">
                <ContentTemplate>
                    <button class="accordion" onclick="closeAccords(this);return false;">Vehicles not reporting in more than 30 days <span class="up"></span><span id="avlGrid30dTotal" class="totalRows"/></button>
		            <div class="accordPanel" style="display:none">
                        <div id="avlTable30d" class="table">
                            <asp:GridView runat="server" ID="avlGrid30d" CellPadding="10" EnableViewState="false" autopostback="true" AutoGenerateColumns="False" class="grid">
                                <Columns>
                                    <asp:BoundField DataField="Mobile ID" HeaderText="Mobile ID" SortExpression="Mobile ID" />
                                    <asp:BoundField DataField="Vehicle Name" HeaderText="Vehicle Name" SortExpression="Vehicle Name" />
                                    <asp:BoundField DataField="Auto Aid ID" HeaderText="Auto Aid ID" SortExpression="Auto Aid ID" />
                                    <asp:BoundField DataField="Lat" HeaderText="Lat" SortExpression="Lat" />
                                    <asp:BoundField DataField="Lon" HeaderText="Lon" SortExpression="Lon" />
                                    <asp:BoundField DataField="AVL Timestamp" HeaderText="AVL Timestamp" SortExpression="AVL Timestamp" />
                                    <asp:BoundField DataField="Connection Type" HeaderText="Connection Type" SortExpression="Connection Type" />
                                </Columns>
                                <HeaderStyle BorderColor="Black" BorderStyle="Solid" BorderWidth="1px" />
                            </asp:GridView>
                        </div>
                        <asp:label runat="server" id="noResults30d" class="hide">No results found.</asp:label>
                    </div>

		            <button class="accordion" onclick="closeAccords(this);return false;">Vehicles not reporting in 14 - 30 days <span class="up"></span><span id="avlGrid14dTotal" class="totalRows"/></button>        
		            <div class="accordPanel" style="display:none">
		                <div id="avlTable14d" class="table">
		                    <asp:GridView runat="server" ID="avlGrid14d" CellPadding="10" EnableViewState="false" autopostback="true" AutoGenerateColumns="False" class="grid">
		                        <Columns>
		                            <asp:BoundField DataField="Mobile ID" HeaderText="Mobile ID" SortExpression="Mobile ID" />
		                            <asp:BoundField DataField="Vehicle Name" HeaderText="Vehicle Name" SortExpression="Vehicle Name" />
		                            <asp:BoundField DataField="Auto Aid ID" HeaderText="Auto Aid ID" SortExpression="Auto Aid ID" />
		                            <asp:BoundField DataField="Lat" HeaderText="Lat" SortExpression="Lat" />
		                            <asp:BoundField DataField="Lon" HeaderText="Lon" SortExpression="Lon" />
		                            <asp:BoundField DataField="AVL Timestamp" HeaderText="AVL Timestamp" SortExpression="AVL Timestamp" />
		                            <asp:BoundField DataField="Connection Type" HeaderText="Connection Type" SortExpression="Connection Type" />
		                        </Columns>
		                        <HeaderStyle BorderColor="Black" BorderStyle="Solid" BorderWidth="1px" />
		                    </asp:GridView>
		                </div>
		                <asp:label runat="server" id="noResults14d" class="hide">No results found.</asp:label>
		            </div>
            
		            <button class="accordion" onclick="closeAccords(this);return false;">Vehicles not reporting in 7 - 14 days <span class="up"></span><span id="avlGrid7dTotal" class="totalRows"/></button>        
		            <div class="accordPanel" style="display:none">
		                <div id="avlTable7d" class="table">
		                    <asp:GridView runat="server" ID="avlGrid7d" CellPadding="10" EnableViewState="false" autopostback="true" AutoGenerateColumns="False" class="grid">
		                        <Columns>
		                            <asp:BoundField DataField="Mobile ID" HeaderText="Mobile ID" SortExpression="Mobile ID" />
		                            <asp:BoundField DataField="Vehicle Name" HeaderText="Vehicle Name" SortExpression="Vehicle Name" />
		                            <asp:BoundField DataField="Auto Aid ID" HeaderText="Auto Aid ID" SortExpression="Auto Aid ID" />
		                            <asp:BoundField DataField="Lat" HeaderText="Lat" SortExpression="Lat" />
		                            <asp:BoundField DataField="Lon" HeaderText="Lon" SortExpression="Lon" />
		                            <asp:BoundField DataField="AVL Timestamp" HeaderText="AVL Timestamp" SortExpression="AVL Timestamp" />
		                            <asp:BoundField DataField="Connection Type" HeaderText="Connection Type" SortExpression="Connection Type" />
		                        </Columns>
		                        <HeaderStyle BorderColor="Black" BorderStyle="Solid" BorderWidth="1px" />
		                    </asp:GridView>
		                </div>
		                <asp:label runat="server" id="noResults7d" class="hide">No results found.</asp:label>
		            </div>

		            <button class="accordion" onclick="closeAccords(this);return false;">Vehicles not reporting in 1 - 7 days <span class="up"></span><span id="avlGrid1dTotal" class="totalRows"/></button>        
		            <div class="accordPanel" style="display:none">
		                <div id="avlTable1d" class="table">
		                    <asp:GridView runat="server" ID="avlGrid1d" CellPadding="10" EnableViewState="false" autopostback="true" AutoGenerateColumns="False" class="grid">
		                        <Columns>
		                            <asp:BoundField DataField="Mobile ID" HeaderText="Mobile ID" SortExpression="Mobile ID" />
		                            <asp:BoundField DataField="Vehicle Name" HeaderText="Vehicle Name" SortExpression="Vehicle Name" />
		                            <asp:BoundField DataField="Auto Aid ID" HeaderText="Auto Aid ID" SortExpression="Auto Aid ID" />
		                            <asp:BoundField DataField="Lat" HeaderText="Lat" SortExpression="Lat" />
		                            <asp:BoundField DataField="Lon" HeaderText="Lon" SortExpression="Lon" />
		                            <asp:BoundField DataField="AVL Timestamp" HeaderText="AVL Timestamp" SortExpression="AVL Timestamp" />
		                            <asp:BoundField DataField="Connection Type" HeaderText="Connection Type" SortExpression="Connection Type" />
		                        </Columns>
		                        <HeaderStyle BorderColor="Black" BorderStyle="Solid" BorderWidth="1px" />
		                    </asp:GridView>
		                </div>
		                <asp:label runat="server" id="noResults1d" class="hide">No results found.</asp:label>
		            </div>

		            <button class="accordion" onclick="closeAccords(this);return false;">Vehicles reporting in last 24 hours <span class="up"></span><span id="avlGrid24hTotal" class="totalRows"/></button>        
		            <div class="accordPanel" style="display:none">
		                <div id="avlTable24h" class="table">
		                    <asp:GridView runat="server" ID="avlGrid24h" CellPadding="10" EnableViewState="false" autopostback="true" AutoGenerateColumns="False" class="grid">
		                        <Columns>
		                            <asp:BoundField DataField="Mobile ID" HeaderText="Mobile ID" SortExpression="Mobile ID" />
		                            <asp:BoundField DataField="Vehicle Name" HeaderText="Vehicle Name" SortExpression="Vehicle Name" />
		                            <asp:BoundField DataField="Auto Aid ID" HeaderText="Auto Aid ID" SortExpression="Auto Aid ID" />
		                            <asp:BoundField DataField="Lat" HeaderText="Lat" SortExpression="Lat" />
		                            <asp:BoundField DataField="Lon" HeaderText="Lon" SortExpression="Lon" />
		                            <asp:BoundField DataField="AVL Timestamp" HeaderText="AVL Timestamp" SortExpression="AVL Timestamp" />
		                            <asp:BoundField DataField="Connection Type" HeaderText="Connection Type" SortExpression="Connection Type" />
		                        </Columns>
		                        <HeaderStyle BorderColor="Black" BorderStyle="Solid" BorderWidth="1px" />
		                    </asp:GridView>
		                </div>
		                <asp:label runat="server" id="noResults24h" class="hide">No results found.</asp:label>
		            </div>
            
		            <button class="accordion" onclick="closeAccords(this);return false;">All Vehicles <span class="up"></span><span id="avlGridAllTotal" class="totalRows"/></button>
		            <div class="accordPanel" style="display:none">
		                <div id="avlTableAll" class="table">
		                    <asp:GridView runat="server" ID="avlGridAll" CellPadding="10" EnableViewState="false" autopostback="true" AutoGenerateColumns="False" class="grid">
		                        <Columns>
		                            <asp:BoundField DataField="Mobile ID" HeaderText="Mobile ID" SortExpression="Mobile ID" />
		                            <asp:BoundField DataField="Vehicle Name" HeaderText="Vehicle Name" SortExpression="Vehicle Name" />
		                            <asp:BoundField DataField="Auto Aid ID" HeaderText="Auto Aid ID" SortExpression="Auto Aid ID" />
		                            <asp:BoundField DataField="Lat" HeaderText="Lat" SortExpression="Lat" />
		                            <asp:BoundField DataField="Lon" HeaderText="Lon" SortExpression="Lon" />
		                            <asp:BoundField DataField="AVL Timestamp" HeaderText="AVL Timestamp" SortExpression="AVL Timestamp" />
		                            <asp:BoundField DataField="Connection Type" HeaderText="Connection Type" SortExpression="Connection Type" />
		                        </Columns>
		                        <HeaderStyle BorderColor="Black" BorderStyle="Solid" BorderWidth="1px" />
		                    </asp:GridView>
		                </div>
		                <asp:label runat="server" id="noResultsAll" class="hide">No results found.</asp:label>
		            </div>
		            <div class="buffer"></div>
                </ContentTemplate>
            </asp:UpdatePanel>
        </div>
	</div>
    <div class="backPanel">
        <div class="backTop">Additional Resources</div>
        <div title="Additional AVL Resources">
            <p><a href="http://calfireweb/organization/fireprotection/avl/">AVL/MDT Project Page</a></p>
            <p><a href="http://calfireweb/organization/managementservices/its/">ITS Home Page</a></p>
            <p><a href="http://calfireweb/applications/cad/cadsupport.shtml">CAD Support</a></p>
        </div>
    </div>
</form>
<script type="text/javascript" src="./js/Accordion.js"></script>
<script type="text/javascript">

    function closeAccords(sender) {
        //hide other buttons if button clicked isnt active
        if (sender.className == 'accordion active') {
            $("#closebtn").addClass('hide');
            $.each($(".down"),
                function (i, el) {
                    $(el).removeClass('down');
                    $(el).addClass('up');
                });
            $.each($(".accordion"),
                function(i, el) {
                    if (el != sender) {
                        $(el).removeClass('hide');
                    }
                });
        } else if (sender.className == 'accordion') {
            $.each($(".up"),
                function (i, el) {
                    $(el).removeClass('up');
                    $(el).addClass('down');
                });
            $.each($(".accordion"),
                function(i, el) {
                    if (el != sender) {
                        $(el).addClass('hide');
                    }
                });
        }
        $.each($(".accordPanel"),
            function (i, el) {
                el.scrollTop = 0;
            });
    }

    function initDataTable() {
        var today = new Date();
        var dd = String(today.getDate());
        var mm = String(today.getMonth() + 1);
        var yyyy = String(today.getFullYear());
        if (mm < 10) {
            mm = "0" + mm;
        }
        if (dd < 10) {
            dd = "0" + dd;
        }
        var tableOptions = {
            orderCellsTop: true,
            "aaSorting": [[1, "asc"]],
            "bPaginate": false,
            dom: 'Bfrtip',
            "bAutoWidth": false,
            buttons: [
                {
                    extend: 'excelHtml5',
                    title: 'AVL_Information_' + mm + dd + yyyy,
                    text: 'Export to Excel',
                    sheetName: 'AVLInformation'
                },
                {
                    text: 'Clear Search',
                    className: 'clearSearchBtn',
                    action: function (e, dt) {
                        dt
                            .search('')
                            .columns().search('')
                            .draw();
                        $('.fieldSearch').val('');
                    }
                }
            ]
            , "autowidth": false
            ,
            "columns": [
                { "width": "5%" },
                { "width": "5%" },
                { "width": "5%" },
                { "width": "5%" },
                { "width": "5%" },
                { "width": "5%" },
                { "width": "5%" }
            ]
        }
        var tableList = ['avlGrid30d', 'avlGrid14d', 'avlGrid7d', 'avlGrid1d', 'avlGrid24h', 'avlGridAll'];
        $.each($(tableList),
            function (i, el) {
                tableBuilder(el, tableOptions, 'yes');
                var foundStr = " records found)";
                var numRows = $("#" + el + " tr").length - 2;
                if (numRows < 0) numRows = 0;
                if (numRows == 1) foundStr = " record found)";
                $('#' + el + 'Total').text("(" + numRows + foundStr);
            });
    }

    window.onload = initDataTable();
</script>
</body>
</html>


<!--
    

Format for linking:
https://maps.google.com/?q=38.6531004,-90.243462&ll=38.6531004,-90.243462&z=3
    -->