using System;
using System.Linq;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using ITfoxtec.Identity.Saml2.MvcCore.Configuration;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Util;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;

namespace saml2
{
    public class Startup
    {
        public static IWebHostEnvironment AppEnvironment { get; private set; }
        public Startup(IWebHostEnvironment env, IConfiguration configuration)
        {
            AppEnvironment = env;
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddRazorPages();

            services.Configure<Saml2Configuration>(Configuration.GetSection("Saml2"));

            services.Configure<Saml2Configuration>(saml2Config =>
            {
                // const string certHeader = "-----BEGIN CERTIFICATE-----";
                // const string certFooter = "-----END CERTIFICATE-----";
                const string keyHeader = "-----BEGIN PRIVATE KEY-----";
                const string keyFooter = "-----END PRIVATE KEY-----";
                var certPem = CertificateUtil.Load(Configuration["Saml2:SigningCert"]);
                var keyPem = File.ReadAllText(Configuration["Saml2:SigningKey"]);

                // var certBase64 = certPem.Replace(certHeader, "").Replace(certFooter, "");
                var keyBase64 = keyPem.Replace(keyHeader, "").Replace(keyFooter, "");

                var key = RSA.Create();
                key.ImportPkcs8PrivateKey(Convert.FromBase64String(keyBase64), out _);

                var cert = new X509Certificate2(certPem).CopyWithPrivateKey(key);

                saml2Config.SigningCertificate = cert;
                saml2Config.SignAuthnRequest = false;
                saml2Config.AllowedAudienceUris.Add(saml2Config.Issuer);
                saml2Config.AllowedIssuer = Configuration["Saml2:IdPIssuer"];

                var entityDescriptor = new EntityDescriptor();
                entityDescriptor.ReadIdPSsoDescriptorFromUrl(new Uri(Configuration["Saml2:IdPMetadataUrl"]));

                if (entityDescriptor.IdPSsoDescriptor != null)
                {
                    // saml2Config.SingleSignOnDestination = entityDescriptor.IdPSsoDescriptor.SingleSignOnServices.First().Location;
                    saml2Config.SingleSignOnDestination = entityDescriptor.IdPSsoDescriptor.SingleSignOnServices.Where(l => l.Binding.AbsoluteUri == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect").First().Location;
                    saml2Config.SignatureValidationCertificates.AddRange(entityDescriptor.IdPSsoDescriptor.SigningCertificates);
                }
                else
                {
                    throw new Exception("IDPSSODescriptor not loaded from metadata");
                }
            });

            services.AddSaml2();
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

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseSaml2();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapRazorPages();

                endpoints.MapDefaultControllerRoute();
            });
        }
    }
}
