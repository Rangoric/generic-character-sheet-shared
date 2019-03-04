namespace Utilities.Jwt

open Microsoft.IdentityModel.Protocols
open Microsoft.IdentityModel.Protocols
open Microsoft.IdentityModel.Protocols.OpenIdConnect
open System.Net.Http.Headers
open Microsoft.IdentityModel.Tokens
open System.Threading
open System.Threading.Tasks
open System.IdentityModel.Tokens.Jwt
open Microsoft.IdentityModel.Tokens
open System

module JWTSecurity =
    let Setup configurationUrl audience issuer =
        let configuration =
            let documentRetriever = HttpDocumentRetriever();
            documentRetriever.RequireHttps <- true
            new ConfigurationManager<OpenIdConnectConfiguration>(
                configurationUrl,
                OpenIdConnectConfigurationRetriever(),
                documentRetriever)
        let validationParameter =
            let result = TokenValidationParameters()
            result.RequireSignedTokens <- true
            result.ValidAudience <- audience
            result.ValidateAudience <- true
            result.ValidIssuer <- issuer
            result.ValidateIssuer <- true
            result.ValidateIssuerSigningKey <- true
            result.ValidateLifetime <- true
            result.IssuerSigningKeys <- 
                (configuration.GetConfigurationAsync(CancellationToken.None)
                |> Async.AwaitTask
                |> Async.RunSynchronously).SigningKeys
            result       
        let rec authorize (header:AuthenticationHeaderValue) = 
                match header with
                | null -> false
                | _ ->
                    match header.Scheme with
                    | "Bearer" ->
                        let handler = JwtSecurityTokenHandler()
                        try
                            handler.ValidateToken(header.Parameter, validationParameter) |> ignore
                            true
                        with
                            | :? SecurityTokenSignatureKeyNotFoundException ->
                                configuration.RequestRefresh()
                                authorize header
                            | _ -> false
                    | _ -> false
        authorize
    let SetupWithEnvironmentVariable:(AuthenticationHeaderValue -> bool) =
        Setup
            (Environment.GetEnvironmentVariable "Authorization-Configuration-Url")
            (Environment.GetEnvironmentVariable "Authorization-ClientID")
            (Environment.GetEnvironmentVariable "Authorization-Issuer")
