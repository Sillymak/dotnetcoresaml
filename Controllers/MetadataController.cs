

using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;

namespace saml2.Controllers
{
    [AllowAnonymous]
    [Route("Metadata")]
    public class MetadataController : Controller
    {
        private readonly Saml2Configuration config;

        public MetadataController(IOptions<Saml2Configuration> configAccessor)
        {
            config = configAccessor.Value;
        }

        public IActionResult Index()
        {
            var defaultSite = new Uri($"{Request.Scheme}://{Request.Host.ToUriComponent()}/");

            var entityDescriptor = new EntityDescriptor(config, false);
            // entityDescriptor.ValidUntil = 3650;
            entityDescriptor.SPSsoDescriptor = new SPSsoDescriptor
            {
                WantAssertionsSigned = false,
                SigningCertificates = new X509Certificate2[]
                {
                    config.SigningCertificate
                },
                SingleLogoutServices = new SingleLogoutService[]
                {
                    new SingleLogoutService { Binding = ProtocolBindings.HttpPost, Location = new Uri(defaultSite, "auth/SingleLogout"), ResponseLocation = new Uri(defaultSite, "auth/LoggedOut") }
                },
                NameIDFormats = new Uri[] 
                { 
                    NameIdentifierFormats.Email,
                    NameIdentifierFormats.Persistent,
                    NameIdentifierFormats.Transient
                },
                AssertionConsumerServices = new AssertionConsumerService[]
                {
                    new AssertionConsumerService { Binding = ProtocolBindings.HttpPost, Location = new Uri(defaultSite, "auth/acs"), IsDefault = true },
                    new AssertionConsumerService { Binding = ProtocolBindings.HttpPost, Location = new Uri(defaultSite, "auth/acs2") },
                    new AssertionConsumerService { Binding = ProtocolBindings.HttpPost, Location = new Uri(defaultSite, "auth/acs3") }
                },
                AttributeConsumingServices = new AttributeConsumingService[]
                {
                    new AttributeConsumingService { ServiceName = new ServiceName("Saml2 Dotnet", "en"), RequestedAttributes = CreateRequestedAttributes() }
                }
                
            };

            entityDescriptor.ContactPersons = new []
            {
                new ContactPerson(ContactTypes.Administrative)
                {
                    Company = "A Company",
                    GivenName = "First name",
                    SurName = "Last name",
                    EmailAddress = "some@example.com",
                    TelephoneNumber = "some phone number"
                },
                new ContactPerson(ContactTypes.Technical)
                {
                    Company = "A Company",
                    GivenName = "First name",
                    SurName = "Last name",
                    EmailAddress = "some2@example.com",
                    TelephoneNumber = "some other phone number"
                }
            };

            return new Saml2Metadata(entityDescriptor).CreateMetadata().ToActionResult();
        }

        private IEnumerable<RequestedAttribute> CreateRequestedAttributes()
        {
            yield return new RequestedAttribute("urn:oid:1.3.6.1.4.1.5923.1.1.1.6", true, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
            yield return new RequestedAttribute("urn:oid:1.3.6.1.4.1.5923.1.1.1.1", false, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
            yield return new RequestedAttribute("urn:oid:2.5.4.4", false, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
            yield return new RequestedAttribute("urn:oid:2.5.4.42", false, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
            yield return new RequestedAttribute("urn:oid:0.9.2342.19200300.100.1.3", false, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
        }
    }
}