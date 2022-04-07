using System;
using System.Configuration;
using System.Data.SqlClient;
using System.Web.UI.WebControls;

namespace AVLReport {
    public partial class Default : System.Web.UI.Page {
        private readonly string sqldb = ConfigurationManager.ConnectionStrings["AVL"].ConnectionString;
        private readonly DateTime today = DateTime.Now;
        private bool useEcc;
        private Parameter ecc;

        protected void Page_Load(object sender, EventArgs e)
        {
            string baseQry =
                "Select [Mobile ID],[Vehicle Name],[Auto Aid ID],Lat,Lon,[AVL Timestamp],[Connection Type] from Mobile_AVL_Update_View WHERE ";
            try
            {
                if (!IsPostBack)
                {
                    //set up eccDdl
                    using (SqlConnection testconn = new SqlConnection(sqldb))
                    {
                        string qryEcc =
                            "Select distinct LEFT([Auto Aid ID], 3) from Mobile_AVL_Update_View ORDER BY LEFT([Auto Aid ID], 3) ASC";
                        using (SqlCommand cmd = new SqlCommand(qryEcc, testconn))
                        {
                            testconn.Open();
                            using (SqlDataReader reader = cmd.ExecuteReader())
                            {
                                while (reader.Read())
                                {
                                    eccDdl.Items.Add(new ListItem(reader.GetString(0), reader.GetString(0)));
                                }
                            }
                        }
                    }
                    eccDdl.Items.Remove("A/T");
                    eccDdl.Items.Remove("AFF");
                    eccDdl.Items.Remove("AMU");
                }
                else if (eccDdl.SelectedIndex != 0) {
                    ecc = new Parameter {
                        Name = "ecc",
                        DefaultValue = eccDdl.SelectedValue
                    };
                    baseQry += "LEFT([Auto Aid ID], 3) = @ecc AND ";
                    useEcc = true;
                }

                //Configure GridView- 30+ days
                string qry = baseQry + "[AVL Timestamp] < '" + today.AddMonths(-1).ToString("yyyy-MM-dd HH:mm:ss.fff") + "'";
                SetGridSource(avlGrid30d, qry);
                avlGrid30d.DataBind();
                try {
                    noResults30d.CssClass = "hide";
                    avlGrid30d.HeaderRow.TableSection = TableRowSection.TableHeader;
                } catch {
                    noResults30d.CssClass = "invalid-msg";
                }

                //Configure GridView- 14-30 days
                qry = baseQry + "[AVL Timestamp] > '" + today.AddMonths(-1).ToString("yyyy-MM-dd HH:mm:ss.fff") +
                      "' AND [AVL Timestamp] < '" + today.AddDays(-14).ToString("yyyy-MM-dd HH:mm:ss.fff") + "'";
                SetGridSource(avlGrid14d, qry);
                avlGrid14d.DataBind();
                try {
                    noResults14d.CssClass = "hide";
                    avlGrid14d.HeaderRow.TableSection = TableRowSection.TableHeader;
                }
                catch
                {
                    noResults14d.CssClass = "invalid-msg";
                }

                //Configure GridView- 7-14 days
                qry = baseQry + "[AVL Timestamp] > '" + today.AddDays(-14).ToString("yyyy-MM-dd HH:mm:ss.fff") +
                      "' AND [AVL Timestamp] < '" + today.AddDays(-7).ToString("yyyy-MM-dd HH:mm:ss.fff") + "'";
                SetGridSource(avlGrid7d, qry);
                avlGrid7d.DataBind();
                try {
                    noResults7d.CssClass = "hide";
                    avlGrid7d.HeaderRow.TableSection = TableRowSection.TableHeader;
                }
                catch
                {
                    noResults7d.CssClass = "invalid-msg";
                }

                //Configure GridView- 1-7 days
                qry = baseQry + "[AVL Timestamp] > '" + today.AddDays(-7).ToString("yyyy-MM-dd HH:mm:ss.fff") +
                      "' AND [AVL Timestamp] < '" + today.AddDays(-1).ToString("yyyy-MM-dd HH:mm:ss.fff") + "'";
                SetGridSource(avlGrid1d, qry);
                avlGrid1d.DataBind();
                try {
                    noResults1d.CssClass = "hide";
                    avlGrid1d.HeaderRow.TableSection = TableRowSection.TableHeader;
                }
                catch
                {
                    noResults1d.CssClass = "invalid-msg";
                }

                //Configure GridView- less than 1 day
                qry = baseQry + "[AVL Timestamp] > '" + today.AddDays(-1).ToString("yyyy-MM-dd HH:mm:ss.fff") +
                      "' AND [AVL Timestamp] < '" + today.ToString("yyyy-MM-dd HH:mm:ss.fff") + "'";
                SetGridSource(avlGrid24h, qry);
                avlGrid24h.DataBind();
                try {
                    noResults24h.CssClass = "hide";
                    avlGrid24h.HeaderRow.TableSection = TableRowSection.TableHeader;
                }
                catch
                {
                    noResults24h.CssClass = "invalid-msg";
                }

                //Configure GridView- all records
                qry = baseQry + "1=1";
                SetGridSource(avlGridAll, qry);
                avlGridAll.DataBind();
                try {
                    noResultsAll.CssClass = "hide";
                    avlGridAll.HeaderRow.TableSection = TableRowSection.TableHeader;
                }
                catch
                {
                    noResultsAll.CssClass = "invalid-msg";
                }

                dateField.InnerHtml = "Report last generated <b class='dateTime'>" + DateTime.Now.ToString("MMM dd, yyyy hh:mm:ss" + "</b>.");
            }
            catch
            {
                dateField.InnerText = "An error occured while querying data.";
                dateField.Attributes["style"] = "color: red";
            }
        }

        private void SetGridSource(GridView grid, string qry) {
            using (SqlDataSource ds = new SqlDataSource()) {
                ds.SelectCommand = qry;
                if (useEcc) {
                    ds.SelectParameters.Add(ecc);
                }
                ds.ConnectionString = sqldb;
                grid.DataSource = ds;
            }
        }
    }
}
    
