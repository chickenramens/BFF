using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Threading.Tasks;
using System.Net.Http;
using Microsoft.Extensions.Primitives;
using System.Collections;
using System.Collections.Generic;

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
            _ = app.Use(async (context, next) =>
            {
                try
                {
                    using (HttpClient client = new HttpClient())
                    {
                        if (context.Request.Headers.ContainsKey("Authorization"))
                        {
                            ;
                        } else if (context.Session.GetString("access_token") != null)
                        {
                            // set authorization header
                            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", context.Session.GetString("access_token"));
                        }
                        else
                        {
                            context.Response.StatusCode = 401;
                            return;
                        }

                        HttpResponseMessage response = null;
                        var url = $"{Configuration["Proxy:Url"]}{context.Request.Path}";
                        var queryString = context.Request.QueryString.ToString();
                        if (!string.IsNullOrEmpty(queryString))
                        {
                            url += queryString;
                        }

                        HttpContent content = null;
                        switch(context.Request.Method.ToLower())
                        {
                            case "post":
                            case "put":
                                content = new StreamContent(context.Request.Body);
                                break;

                        }

                        // set request headers from the client
                        foreach (var header in context.Request.Headers)
                        {
                            if (header.Key.ToLower() == "host" || header.Key.ToLower() == "accept-encoding")
                            {
                                continue;
                            }
                            var values = new ArrayList();

                            foreach (var value in header.Value)
                            {
                                values.Add(value);
                            }

                            IEnumerable<string> v = new StringValues(values.ToArray(typeof(string)) as string[]);

                            switch (context.Request.Method.ToLower())
                            {
                                case "post":
                                case "put":
                                    if (header.Key.ToLower().StartsWith("content-"))
                                    {
                                        content.Headers.Add(header.Key, v);
                                    }
                                    else
                                    {
                                        client.DefaultRequestHeaders.Add(header.Key, v);
                                    }
                                    break;
                                default:
                                    if (!header.Key.ToLower().StartsWith("content-")) { 
                                        client.DefaultRequestHeaders.Add(header.Key, v);
                                    }
                                    break;
                            }
                        }

                        if (context.Request.Method.ToLower() == "get")
                        {
                            response = await client.GetAsync(url);
                        }
                        else if (context.Request.Method.ToLower().Equals("post"))
                        {
                            response = await client.PostAsync(url, content);
                        }
                        else if(context.Request.Method.ToLower().Equals("put"))
                        {
                            response = await client.PutAsync(url, content);
                        }
                        else if (context.Request.Method.ToLower().Equals("delete"))
                        {
                            response = await client.DeleteAsync(url);
                        }

                        context.Response.StatusCode = (int)response.StatusCode;

                        //write response headers to the client
                        foreach (var header in response.Headers)
                        {
                            var values = new ArrayList();

                            foreach (var value in header.Value)
                            {
                                values.Add(value);
                            }
                            context.Response.Headers.Add(header.Key, new StringValues(values.ToArray(typeof(string)) as string[]));
                        }

                        //write the response to the client
                        await response.Content.CopyToAsync(context.Response.Body);

                        return;
                    }
                }
                catch (Exception ex)
                {
                    context.Response.StatusCode = 500;
                    await context.Response.WriteAsync(ex.Message);
                    return;
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
            options.ResponseType = OpenIdConnectResponseType.Code;
            options.UsePkce = true;


            // Configure the scope
            options.Scope.Clear();
            options.Scope.Add("openid");

            options.CallbackPath = new PathString("/signin-oidc");

            // Configure the Claims Issuer to be Auth0
            options.ClaimsIssuer = "Auth0";
            
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
                OnTokenValidated = context =>
                {
                    context.HttpContext.Session.SetString("id_token", context.TokenEndpointResponse.IdToken);
                    context.HttpContext.Session.SetString("access_token", context.TokenEndpointResponse.AccessToken);
                    context.HttpContext.Session.SetString("refresh_token", context.TokenEndpointResponse.RefreshToken);
                    
                    return Task.CompletedTask;
                }
            };
        }
    }
}
