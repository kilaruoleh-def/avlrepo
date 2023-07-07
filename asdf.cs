using Hangfire;
using Hangfire.MySql;
using Hangfire.SqlServer;
using IHM.Filters;
using IHM.Handler;
using IHM.Service;
using IHM.Service.Audio;
using IHM.Service.Schedule;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NLog;
using NLog.Config;
using NLog.Targets;
using PCAdmin.AppServer.Client;
using PCAdmin.AppServer.Client.Interfaces.ServiceInterfaces;
using PCAdmin.AppServer.Client.Services;
using SwitchBoard.Client;
using System;
using System.IO;
using System.Transactions;
using WeBuildThings.Core.Exceptions;
using WeBuildThings.XAF.Common;

namespace IHM
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            var config = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("ENVIRONMENT")}.json", optional: true, reloadOnChange: true)
                .AddEnvironmentVariables()
                .Build();

            services.AddCors(options =>
            {
                options.AddPolicy("AllowAllOrigins",
                    builder =>
                    {
                        builder.AllowAnyOrigin()
                        .AllowAnyMethod()
                        .AllowAnyHeader();
                    });
            });

            // response caching
            services.AddResponseCaching();

            // CORS issue fix https://github.com/dotnet/aspnetcore/issues/9348
            services.AddRouting(r => r.SuppressCheckForUnhandledSecurityMetadata = true);

            services.AddAuthentication("Basic").AddScheme<BasicAuthenticationOptions, BasicAuthenticationHandler>("Basic", null);

            services.AddHangfire(ConfigureHangfire);
            services.AddHangfireServer(x => x.StopTimeout = TimeSpan.FromSeconds(10));

            //Dependecy Injection

            services.AddSingleton<IAuthenticationService, PCAdmin.AppServer.Client.Services.AuthenticationService>();
            services.AddSingleton<IPCAdminClient, PCAdminClient>();
            services.AddSingleton<ICallService, CallService>();
            services.AddSingleton<IScheduler, Scheduler>();
            services.AddSingleton<IAudioStorage, AudioStorage>();

            //services.AddSingleton<IScriptBuilder, ScriptBuilder>();
            services.AddSingleton<IHoldTimeService, HoldTimeService>();
            services.AddSingleton<IPCAdminAuthentication, PCAdminAuthentication>();
            services.AddSingleton<CacheProvider, CacheProvider>();
            services.AddSingleton<IExceptionFactory, ExceptionFactory>();

            var assemblies = PCAdmin.AppServer.Client.Services.AuthenticationService.Assemblies;
            var session = ConnectionHelper.CreateSession(config.GetConnectionString("ConnectionString"), assemblies);

            var switchboardSystemSettings = SystemSettings.GetInstance<SwitchBoardSystemSettings>(session);
            var ihmSystemSettings = SystemSettings.GetInstance<IHMSystemSettings>(session);
            var switchboardClientSettings = new SwitchBoardClientSettings
            {
                Url = switchboardSystemSettings.ApiUrl,
                ApplicationName = switchboardSystemSettings.ApplicationName,
                LogPath = switchboardSystemSettings.LogPath,
                ApplicationLoggingEnabled = switchboardSystemSettings.ApplicationLoggingEnabled,
                SecurityLoggingEnabled = switchboardSystemSettings.SecurityLoggingEnabled,
                PhiLoggingEnabled = switchboardSystemSettings.PHILoggingEnabled,
                PciLoggingEnabled = switchboardSystemSettings.PCILoggingEnabled,
                OtherLoggingEnabled = switchboardSystemSettings.OtherLoggingEnabled,
                LocalLoggingConfiguration = GetNLogLoggingConfiguration(ihmSystemSettings),
                IsDatabaseLoggingEnabled = ihmSystemSettings.IsDatabaseLoggingEnabled,
                Username = switchboardSystemSettings.UserName,
                Password = switchboardSystemSettings.Password

            };
            var loggerInstance = new LoggerInstance(switchboardClientSettings);
            services.AddSingleton<ILoggerInstance>(loggerInstance);
            services.AddSingleton<WeBuildThings.Core.Common.Interfaces.ILogger>(loggerInstance);

            services.AddMvc(o => o.Filters.Add(typeof(ExpectedExceptionFilterAttribute)));
            services.AddControllers()
                .AddApplicationPart(typeof(WeBuildThings.XAF.WorkflowEngine.Controllers.WorkflowApiController).Assembly)
                .AddNewtonsoftJson();
            services.AddSwaggerGen(options => { options.CustomSchemaIds(type => type.ToString()); });
            services.AddSwaggerGenNewtonsoftSupport();
        }

        private void ConfigureHangfire(IGlobalConfiguration options)
        {
            var connectionString = Configuration.GetConnectionString("Hangfire");
            IGlobalConfiguration configuration;

            if (ConnectionHelper.IsMySQL)
            {
                configuration = options.UseStorage(new MySqlStorage(connectionString, new MySqlStorageOptions
                {
                    TransactionIsolationLevel = IsolationLevel.ReadCommitted,
                    QueuePollInterval = TimeSpan.FromMilliseconds(500),
                    JobExpirationCheckInterval = TimeSpan.FromHours(1),
                    CountersAggregateInterval = TimeSpan.FromMinutes(5),
                    PrepareSchemaIfNecessary = true,
                    DashboardJobListLimit = 50000,
                    TransactionTimeout = TimeSpan.FromMinutes(1),
                    TablesPrefix = "Hangfire"
                }));
            }
            else
            {
                configuration = options.UseSqlServerStorage(connectionString, new SqlServerStorageOptions
                {
                    CommandBatchMaxTimeout = TimeSpan.FromMinutes(5),
                    SlidingInvisibilityTimeout = TimeSpan.FromMinutes(5),
                    QueuePollInterval = TimeSpan.FromMilliseconds(500),
                    UseRecommendedIsolationLevel = true,
                    UsePageLocksOnDequeue = true,
                    DisableGlobalLocks = true,
                    EnableHeavyMigrations = false
                });
            }

            configuration.UseNLogLogProvider()
                .SetDataCompatibilityLevel(CompatibilityLevel.Version_170)
                .UseSimpleAssemblyNameTypeSerializer();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
                app.UseHsts();
            // https://learn.microsoft.com/en-us/aspnet/core/security/enforcing-ssl?view=aspnetcore-7.0&tabs=visual-studio#require-https
            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseForwardedHeaders(new ForwardedHeadersOptions
            {
                ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
            });
            app.Use(async (context, next) =>
            {
                context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
                context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'");
                context.Response.GetTypedHeaders().CacheControl = new Microsoft.Net.Http.Headers.CacheControlHeaderValue { NoCache = true, NoStore = true };
                context.Response.Headers[Microsoft.Net.Http.Headers.HeaderNames.Vary] = new[] { "Accept-Encoding" };
                await next();
            });
            app.UseCors();
            app.UseResponseCaching(); // Warning: UseCors must be called before UseResponseCaching when using CORS middleware.
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseHangfireDashboard();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
                endpoints.MapGet("/", async context =>
                {
                    await context.Response.WriteAsync("Insurance Hold Manager API");
                });
            });
        }

        private LoggingConfiguration GetNLogLoggingConfiguration(IHMSystemSettings settings)
        {
            LogManager.ThrowExceptions = true;
            var config = new LoggingConfiguration();

            if (settings.IsDatabaseLoggingEnabled)
            {
                var databaseTarget = new DatabaseTarget
                {
                    Name = "database",
                    ConnectionString = settings.DatabaseLoggingConnectionString,
                    CommandType = System.Data.CommandType.StoredProcedure,
                    CommandText = "WriteServiceLog"
                };

                if (ConnectionHelper.IsMySQL)
                {
                    databaseTarget.DBProvider = "MySql.Data.MySqlClient.MySqlConnection, MySql.Data";
                }

                databaseTarget.Parameters.Add(new DatabaseParameterInfo("@Timestamp", "${date}"));
                databaseTarget.Parameters.Add(new DatabaseParameterInfo("@MachineName", "${machinename}"));
                databaseTarget.Parameters.Add(new DatabaseParameterInfo("@Callsite", "${callsite}"));
                databaseTarget.Parameters.Add(new DatabaseParameterInfo("@Logger", "${logger}"));
                databaseTarget.Parameters.Add(new DatabaseParameterInfo("@Level", "${level}"));
                databaseTarget.Parameters.Add(new DatabaseParameterInfo("@Message", "${message}"));
                databaseTarget.Parameters.Add(new DatabaseParameterInfo("@Exception", "${exception:tostring}"));
                config.AddTarget(databaseTarget);
                config.AddRule(LogLevel.Debug, LogLevel.Fatal, "database");
            }

            config.AddTarget(new ConsoleTarget("logconsole"));
            config.AddRule(LogLevel.Debug, LogLevel.Fatal, "logconsole");
            return config;
        }
    }
}
