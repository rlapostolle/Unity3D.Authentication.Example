using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using IdentityModel.Client;
using IdentityModel.OidcClient;
using IdentityModel.OidcClient.Browser;
using IdentityModel.OidcClient.Infrastructure;
using IdentityModel.OidcClient.Results;
using UnityEngine;

namespace Assets
{
    public class UnityAuthClient
    {
        private OidcClient _client;
        private LoginResult _result;

        public UnityAuthClient(bool trust_certificate)
        {
            // We must disable the IdentityModel log serializer to avoid Json serialize exceptions on IOS.
#if UNITY_IOS
            LogSerializer.Enabled = false;
#endif

            // On Android, we use Chrome custom tabs to achieve single-sign on.
            // On Ios, we use SFSafariViewController to achieve single-sign-on.
            // See: https://www.youtube.com/watch?v=DdQTXrk6YTk
            // And for unity integration, see: https://qiita.com/lucifuges/items/b17d602417a9a249689f (Google translate to English!)
#if UNITY_ANDROID
            Browser = new AndroidChromeCustomTabBrowser();
#elif UNITY_IOS
            Browser = new SFSafariViewBrowser();
#endif
            CertificateHandler.Initialize(trust_certificate);
        }

        // Instead of using AppAuth, which is not available for Unity apps, we are using
        // this library: https://github.com/IdentityModel/IdentityModel.OidcClient2
        // .Net 4.5.2 binaries have been built from the above project and included in
        // /Assets/Plugins folder.
        private OidcClient CreateAuthClient()
        {
#if UNITY_ANDROID || UNITY_IOS
            var options = new OidcClientOptions()
            {
                Authority = "https://152.228.212.131:8443/realms/mindbug",
                
                // NOTE: This config was modified from the ones in examples.
                // Using the values in the examples for `OidcClientOptions`
				// was giving "unauthorized client unknown client or client not enabled" error
				// the first time page was loaded.
				//
				// The value for `ClientId` id is modified, and the key `ClientSecret`
				// (which was omitted) is added.
				// See: https://stackoverflow.com/a/65198297/3622300
				//
				// Probably a setup change was not reflected in existing examples.
                ClientId = "mindbug.app",
                //ClientSecret = "secret",
                
                Scope = "openid profile email",
                // Redirect (reply) uri is specified in the AndroidManifest and code for handling
                // it is in the associated AndroidUnityPlugin project, and OAuthUnityAppController.mm.
                RedirectUri = "io.identitymodel.native://callback",
                PostLogoutRedirectUri = "io.identitymodel.native://callback",
                ResponseMode = OidcClientOptions.AuthorizeResponseMode.Redirect,
                Flow = OidcClientOptions.AuthenticationFlow.AuthorizationCode,
                Browser = Browser,
            };
#else
            var options = new OidcClientOptions
            {
                Authority = "https://152.228.212.131:8443/realms/mindbug",
                ClientId = "mindbug.app",
                Scope = "openid profile email",
                RedirectUri = string.Format("http://127.0.0.1:7890/"),
                Flow = OidcClientOptions.AuthenticationFlow.AuthorizationCode
            };
#endif
            options.LoggerFactory.AddProvider(new UnityAuthLoggerProvider());
            return new OidcClient(options);
        }

        public async Task<bool> LoginAsync()
        {
            _client = CreateAuthClient();
            try
            {
#if UNITY_ANDROID || UNITY_IOS
                _result = await _client.LoginAsync(new LoginRequest());
#else
                // create a redirect URI using an available port on the loopback address.
                // create an HttpListener to listen for requests on that redirect URI.
                UnityEngine.Debug.Log("redirect URI: " + _client.Options.RedirectUri);
                var http = new HttpListener();
                http.Prefixes.Add(_client.Options.RedirectUri);
                UnityEngine.Debug.Log("Listening..");
                http.Start();

                var state = await _client.PrepareLoginAsync();

                UnityEngine.Debug.Log($"Start URL: {state.StartUrl}");

                // open system browser to start authentication
                Process.Start(state.StartUrl);

                // wait for the authorization response.
                var context = await http.GetContextAsync();

                var formData = GetRequestPostData(context.Request);

                // sends an HTTP response to the browser.
                var response = context.Response;
                string responseString = string.Format("<html><head><meta http-equiv='refresh' content='10;url=https://demo.identityserver.io'></head><body>Please return to the app.</body></html>");
                var buffer = Encoding.UTF8.GetBytes(responseString);
                response.ContentLength64 = buffer.Length;
                var responseOutput = response.OutputStream;
                await responseOutput.WriteAsync(buffer, 0, buffer.Length);
                responseOutput.Close();

                UnityEngine.Debug.Log($"Form Data: {formData}");
                _result = await _client.ProcessResponseAsync(formData, state);

                if (_result.IsError)
                {
                    UnityEngine.Debug.Log("\n\nError:\n" + _result.Error);
                }
                else
                {
                    UnityEngine.Debug.Log("\n\nClaims:");
                    foreach (var claim in _result.User.Claims)
                    {
                        UnityEngine.Debug.Log(claim.Type + ": " + claim.Value);
                    }

                    UnityEngine.Debug.Log("Access token:\n:" + _result.AccessToken);

                    if (!string.IsNullOrWhiteSpace(_result.RefreshToken))
                    {
                        UnityEngine.Debug.Log("Refresh token:\n" + _result.RefreshToken);
                    }
                }

                http.Stop();
#endif
            }
            catch (Exception e)
            {
                UnityEngine.Debug.Log("UnityAuthClient::Exception during login: " + e.Message);
                return false;
            }
            finally
            {
                UnityEngine.Debug.Log("UnityAuthClient::Dismissing sign-in browser.");
                Browser?.Dismiss();
            }

            if (_result.IsError)
            {
                UnityEngine.Debug.Log("UnityAuthClient::Error authenticating: " + _result.Error);
            }
            else
            {
                UnityEngine.Debug.Log("UnityAuthClient::AccessToken: " + _result.AccessToken);
                UnityEngine.Debug.Log("UnityAuthClient::RefreshToken: " + _result.RefreshToken);
                UnityEngine.Debug.Log("UnityAuthClient::IdentityToken: " + _result.IdentityToken);
                UnityEngine.Debug.Log("UnityAuthClient::Signed in.");
                return true;
            }

            return false;
        }


        public static string GetRequestPostData(HttpListenerRequest request)
        {
            if (!request.HasEntityBody)
            {
                return null;
            }

            using (var body = request.InputStream)
            {
                using (var reader = new System.IO.StreamReader(body, request.ContentEncoding))
                {
                    return reader.ReadToEnd();
                }
            }
        }

        public async Task<bool> LogoutAsync()
        {
            try
            {
                await _client.LogoutAsync(new LogoutRequest() {
                    BrowserDisplayMode = DisplayMode.Hidden,
                    IdTokenHint = _result.IdentityToken });
                UnityEngine.Debug.Log("UnityAuthClient::Signed out successfully.");
                return true;
            }
            catch (Exception e)
            {
                UnityEngine.Debug.Log("UnityAuthClient::Failed to sign out: " + e.Message);
            }
            finally
            {
                UnityEngine.Debug.Log("UnityAuthClient::Dismissing sign-out browser.");
                Browser?.Dismiss();
                _client = null;
            }

            return false;
        }

        public string GetUserName()
        {
            return _result == null ? "" : _result.User.Identity.Name;
        }

        //FOR SERVER
        public async Task<UserInfoResult> GetIdentity(string token)
        {
            var res = await _client.GetUserInfoAsync(token);
            return res;
        }

        //FOR SERVER
        public async Task<UserInfoResult> GetIdentity()
        {
            var res = await _client.GetUserInfoAsync(_result.AccessToken);
            return res;
        }

        public MobileBrowser Browser { get; }
    }
}
