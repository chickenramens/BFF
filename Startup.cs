using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.SpaServices.ReactDevelopmentServer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Threading.Tasks;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;
using Azure;
using Microsoft.AspNetCore.Http.HttpResults;
using System.IdentityModel.Tokens.Jwt;

namespace BackendForFrontend
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

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddCookie(o =>
            {
                o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                o.Cookie.SameSite = SameSiteMode.Strict;
                o.Cookie.HttpOnly = true;
            })
            .AddOpenIdConnect("OpenIdConnect", options => ConfigureOpenIdConnect(options));


//            services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
//                .AddMicrosoftIdentityWebApp(Configuration.GetSection("AzureAdB2C"));           



            services.AddControllersWithViews();
            

            services.AddHttpClient();
            services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromMinutes(30);
            });

            // In production, the React files will be served from this directory
            services.AddSpaStaticFiles(configuration =>
            {
                configuration.RootPath = "ClientApp/build";
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseSession();

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseSpaStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller}/{action}/{id?}"
                );
                
            });
            /*
            app.UseSpa(spa =>
            {
                spa.Options.SourcePath = "ClientApp";

                if (env.IsDevelopment())
                {
                    spa.UseReactDevelopmentServer(npmScript: "start");
                }
            });
            */
            app.Use(async (context, next) =>
            {
                if (context.Request.Path.StartsWithSegments("/api"))
                {
                    if (!context.User.Identity.IsAuthenticated)
                    {
                        context.Response.StatusCode = 401;
                        return;
                    }
                }
                next(context);
            });
        }

        private void ConfigureOpenIdConnect(OpenIdConnectOptions options)
        {
            // Set the authority to your Auth0 domain
            options.Authority = $"https://{Configuration["Auth0:Domain"]}";

            // Configure the Auth0 Client ID and Client Secret
            options.ClientId = Configuration["Auth0:ClientId"];
//            options.ClientSecret = Configuration["Auth0:ClientSecret"];

            // Set response type to code
//            options.ResponseType = OpenIdConnectResponseType.CodeIdToken;

//            options.ResponseMode = OpenIdConnectResponseMode.FormPost;
            options.ResponseType = OpenIdConnectResponseType.Code;
            options.UsePkce = true;


            // Configure the scope
            options.Scope.Clear();
            options.Scope.Add("openid");
//            options.Scope.Add("offline_access");
//            options.Scope.Add("read:weather");

            // Set the callback path, so Auth0 will call back to http://localhost:3000/callback
            // Also ensure that you have added the URL as an Allowed Callback URL in your Auth0 dashboard
            //            options.CallbackPath = new PathString("/callback");
            options.CallbackPath = new PathString("/signin-oidc");

            // Configure the Claims Issuer to be Auth0
            options.ClaimsIssuer = "Auth0";

            options.SaveTokens = true;

            
            options.Events = new OpenIdConnectEvents
            {
                // handle the logout redirection
                OnRedirectToIdentityProviderForSignOut = (context) =>
                {
                    var logoutUri = $"https://{Configuration["Auth0:Domain"]}/v2/logout?client_id={Configuration["Auth0:ClientId"]}";

                    var postLogoutUri = context.Properties.RedirectUri;
                    if (!string.IsNullOrEmpty(postLogoutUri))
                    {
                        if (postLogoutUri.StartsWith("/"))
                        {
                            // transform to absolute
                            var request = context.Request;
                            postLogoutUri = request.Scheme + "://" + request.Host + request.PathBase + postLogoutUri;
                        }
                        logoutUri += $"&returnTo={ Uri.EscapeDataString(postLogoutUri)}";
                    }
                    context.Response.Redirect(logoutUri);
                    context.HandleResponse();

                    return Task.CompletedTask;
                },
                OnRedirectToIdentityProvider = context => {
                    context.ProtocolMessage.SetParameter("audience", Configuration["Auth0:ApiAudience"]);
                    return Task.CompletedTask;
                },
                OnUserInformationReceived = context =>
                {
                    return Task.CompletedTask;
                },
                OnTokenResponseReceived = context =>
                {
                    return Task.CompletedTask;
                },
                OnTokenValidated = context =>
                {
                    context.HttpContext.Session.SetString("id_token", context.TokenEndpointResponse.IdToken);
                    context.HttpContext.Session.SetString("access_token", context.TokenEndpointResponse.AccessToken);
                    context.HttpContext.Session.SetString("refresh_token", context.TokenEndpointResponse.RefreshToken);
                    //parse accesstoken
                    var handler = new JwtSecurityTokenHandler();
                    var token = handler.ReadJwtToken(context.TokenEndpointResponse.AccessToken);
                    
                    return Task.CompletedTask;
                },
                OnMessageReceived = context =>
                {
                    return Task.CompletedTask;
                },
            };
        }
    }
}
