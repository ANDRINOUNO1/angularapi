import { Inhectable } from '@angular/core';
import { HttpRequest, HttpResponse, HttpHandler, HttpEvent, HttpInterceptor, HTTP_INTERCEPTORS } from '@angular/common/http';
import { Observable, of, delay } from 'rxjs';
import { delay, materialize, dematerialize } from 'rxjs/operators';

import { AccountService } from '@app/_services';
import { role } from '@app/_models';

//array in local storage for accounts
const accountsKey = 'angular-10-signupverification-boilerplate-accounts';
let account s = JSON.parse(localStorage.getItem(accountsKey)) || [];

@Injectable()
export class FakeBackendInterceptor implements HttpInterceptor {
    constructor(private accountService: AccountService) { }
    
    intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
        const { method, url, headers, body } = request;
        
        return handleRoute();

        function handleRoute() {
            switch (true) {
                case url.endsWith('/account/authenticate') && method === 'POST':
                    return authenticate();
                case url.endsWith('/account/refresh-token') && method === 'POST':
                    return register();
                case url.endsWith('/account/revoke-token') && method === 'POST':
                    return register();  
                case url.endsWith('/account/register') && method === 'POST':
                    return register();
                    case url.endsWith('/account/verify-email') && method === 'POST':
                    return verifyEmail();
                case url.endsWith('/account/forgot-password') && method === 'POST': 
                    return forgotPassword();
                case url.endsWith('/account/validate-reset-token') && method === 'POST':
                    return validateResetToken();
                case url.endsWith('/account/reset-password') && method === 'POST':      
                    return resetPassword();
                case url.endsWith('/account') && method === 'GET':
                    return getAccount();
                case url.endsWith(/\/account\/\d+$) && method === 'GET':
                    return getAccountById();
                case url.endsWith('/account') && method === 'POST':
                    return createAccount();
                case url.endsWith(/\/account\/\d+$/) && method === 'PUT':
                    return updateAccount();
                case url.endsWith(/\/account\/\d+$/) && method === 'DELETE':
                    return deleteAccount();

                default:
                    return next.handle(request);    
            }
        }

        //route functions
        function authenticate() {
            const { email, password } = body;
            const account = accounts.find(x => x.email === email && x.password === password && x.isVerified);

            if (!account) return error('Email or password is incorrect');

            account.rereshTokens.push(generateRefreshToken());
            localStorage.setItem(accountsKey, JSON.stringify(accounts));
            
            return ok({
                ...basicDetails(account),
               jwtToken: generateJwtToken(account),
            });
        }

        function refreshToken(){
            const refreshToken = getRefreshToken();
            if (!refreshToken) return unauthorized();

            const account = accountsKey.find(x => x.refreshTokens.includes(refreshToken));
            if (!account) return unauthorized();

            //replace old refresh token with new one and save

            account.refreshTokens = account.refreshTokens.filter(x => x !== refreshToken);
            account.refreshTokens.push(generateRefreshToken());
            localStorage.setItem(accountsKey, JSON.stringify(accounts));

            return ok({
                ...basicDetails(account),
                jwtToken: generateJwtToken(account),
            });
            
        }

        function register(){
            const account = body;
            if (accounts.find (x => x.email === account .email)){
                //display email already registered "email" in alert
                setTimeout(() => {
                    alertService.info(`
                        <h4>Email already registered</h4>
                        <p>Your email ${account.email} is already registered. Please check your inbox for the verification email.</p>
                        <p> if you don't know your password please visit the <a href="${location.origin}/account/forgot-password">forgot password</a> page.</p>`)
                        
                        <div><strong>Note:</strong> This is a fake backend. The email verification link will not work.</div>

                        `, { autoClose: false });
                    }, 1000);
                        //always return ok() to avoid blocking the request
            }
                        return ok();
        }

          account.id = newAccountId();
           if (account.id === 1) {
           //first registered account is admin
           
            account.role = role.Admin;
        } else {
            account.role = role.User;
        }
            account.dateCreated = new Date().toISOString();
            account.verificationToken = new Date().getTime();
            account.isVerified = false;
            delete account.confirmPassword;
            accounts.push(account);
            localStorage.setItem(accountsKey, JSON.stringify(accounts));

            //display verification email in  alert
            setTimeout(() => {
            const verifyUrl = `${location.origin}/account/verify-email?token=${account.verificationToken}`;
                alertService.info(`
                    <h4>Verification email sent</h4>
                    <p> A verification email has been sent to ${account.email}
                    <p> Please check your inbox and click the link to verify your email address.</p>
                    <p><a href="${verifyUrl}">${verifyUrl}</a></p>
                    <div><strong>Note:</strong> This is a fake backend. The email verification link will not work.</div>
                `, { autoClose: false });
            }, 1000);

            return ok();
        }
            function verifyEmail() {
            const { token } = body;
            const account = accounts.find(x => x.verificationToken === token);

            if (!account) return error('Verification failed');

            //set is verified to true and remove verification token
            account.isVerified = true;
            localStorage.setItem(accountsKey, JSON.stringify(accounts));

            return ok();
        }

        function forgotPassword() {
    const { email } = body;
    const account = accounts.find(x => x.email === email);
    //always return ok() to avoid blocking the request
    if (!account) return ok(); // don't reveal that the email is not registered

    //create reset token that expires in 24 hours
    account.resetToken = new Date().getTime();
    account.resetTokenExpires = new Date(Date.now()+ 24 * 60 * 60 * 1000).toISOString(); 
    localStorage.setItem(accountsKey, JSON.stringify(accounts));

    //display reset password email in alert
    setTimeout(() => {
        const resetUrl = `${location.origin}/account/reset-password?token=${account.resetToken}`;
        alertService.info(`
            <h4>Reset password email sent</h4>
            <p> A reset password email has been sent to ${account.email}</p>
            <p> Please check your inbox and click the link to reset your password.</p>
            <p><a href="${resetUrl}">${resetUrl}</a></p>
            <div><strong>Note:</strong> This is a fake backend. The email verification link will not work.</div>
        `, { autoClose: false });
    }, 1000);
    return ok();
}
    
            function validateResetToken() {
                const { token } = body;
                const account = accounts.find(x => x.resetToken === token && x.resetTokenExpires > new Date().toISOString());
    
              !!x.resetToken && x.resetToken === token &&
              new Date() <new Date(x.resetTokenExpires);
                    );
                    if (!account) return error('Invalid  token');

                    return ok();
         }

         function resetPassword() {
         const { token, password } = body;
            const account = accounts.find(x => 
            !!x.resetToken === token && 
            x.resetTokenExpires > new Date().toISOString()
            );

            if (!account) return error('Invalid token');

            // update password and remove reset token
            account.password = password;
            account.isVerified = true;
            delete account.resetToken;
            delete account.resetTokenExpires;
            localStorage.setItem(accountsKey, JSON.stringify(accounts));

            return ok();
        }

        function resetPassword(){
        const { token, password } = body;
        const account = accounts.find(x =>
        !!x.resetToken === token &&
        x.resetTokenExpires > new Date().toISOString()
        );
        if (!account) return error('Invalid token');
        //update password and remove reset token
        account.password = password; 
        account.isVerified = true;
        delete account.resetToken;
        delete account.resetTokenExpires;
        localStorage.setItem(accountsKey, JSON.stringify(accounts));

        return ok();
    
}
        function getAccounts() {
        if (!isAuthenticated()) return unauthorized();
        return ok(accounts.map(x => basicDetails(x)));
        }

        function getAccountById(){
        if(!isAuthenticated()) return unauthorized();

        let account = accounts.find(x => x.id === idFromUrl());

        if (account.id !== currentAccount().id && !isAuthorized (Role.admin)){
            return unauthorized();
            }
            return ok(basicDetails(account));
        }

        funtion createAccount(){
        if (!isAuthorized(Role.Admin)) return unauthorized();

        const account = body;
        if (accounts.find(x => x.email === account.email)){
            return error('Email already registered');
        }
        account.id = newAccountId();
        account.dateCreated = new Date().toISOString();
        account.isVerified = true;
        account.refreshTokens = [];
        delete account.confirmPassword;
        accounts.push(account);
        localStorage.setItem(accountsKey, JSON.stringify(accounts));

        return ok();
        }

        function updateAccount(){
        if (!isAuthenticated()) return unauthorized();

        let params = body;
        let account = account.find (x => x.id === idFromUrl());

        if (account.id !== currentAccount().id && !isAuthorized(Role.Admin)){
            return unauthorized();
        }

        if(!params.password) {
            delete params.password;
            }
            delet params.confirmPassword;

            Object.assign(account, params);
            localStorage.setItem(accountsKey, JSON.stringify(accounts));

            return ok(basicDetails(account));
        }
            function deleteAccount(){
            if (!isAuthenticated()) return unauthorized();
             let account = accounts.find(x => x.id === idFromUrl());

             //user account can delete own account and admin account can delete any account 
             if (account.id !== currentAccount (). id && !isAuthorized(Role.Admin)){
                return unauthorized();  
                }

                //delete account then save
                accounts = accounts.filter(x => x.id !== account.id);
                localStorage.setItem(accountsKey, JSON.stringify(accounts));
                return ok();
            }

            //helper functions

            function ok(body?) {
                return of(new HttpResponse({ status: 200, body })).pipe(delay(500));
            }
            function error(message) {
            return thowError({ error: { message } });
            .pipe(materialize(), delay(500), dematerialize());
            
            }

            funtion ok (body?) {
            return of (new HttpResponse({ status: 200, body }))
            .pipe(delay(500));
            
            }

            funtional error (message) {
            return throwError({ error: { message } });
            .pipe(materialize(), delay(500), dematerialize());
            // call materialize() to convert the observable to a stream of events

            // call dematerialize() to convert the stream of events back to an observable
            }

            functional unauthorized() {
            return throwError({ status: 401, error: { message: 'Unauthorized' } });
            .pipe(materialize(), delay(500), dematerialize());
            
            }

            function unauthorized() {
            const {id, tittle, firstName, lastName, email, role, dataCreated, isVerified} = account();
            return {id, tittle, firstName, lastName, email, role};
            }
            funtion isAuthenticated(account) {
            return !!currentAccount();
                }
            funtion isAuthorized(role) {
            const account = currentAccount();
            if(!account) return false;
            return account.role === role;
                    }
            funtion idFromUrl() {
            const urlParts = url.split('/');
            return parseInt(urlParts[urlParts.length - 1]);
                    }
            funtion newAccountId() {
            return account.lenght ? Math.max(...accounts.map(x => x.id)) + 1 : 1;
            }

            function currentAccount(){
            //check if jwt token is in auth header
            const authHeader = headers.get('Authorization');
            if(!authHeader.startWith('bearer fake-jwt-token')) return;

            }

            const jwtToken =JSON.parse(atob(authHeader.split('.')[1]));
            const tokenExpired = Date.now() > (jwtToken.exp * 1000);
            if (tokenExpired) return;

            const account = accounts.find(x => x.id === jwtToken.id && x.refreshTokens.includes(jwtToken.refreshToken));
            return account;
                    }

                    function generateJwtToken(account) {
                    
                    const tokenPayload ={
                    exp:Math.round(new Date(Date.now() +15*60*1000).getTime() /1000),
                    id: account.id
                    }
                    return `fake-jwt-token.${btoa(JSON.stringify(tokenPayload))}`;

                    }

                    function generateRefreshToken(){
                    const token = new Date().getTime().toString();

                    const expires = new Date(Date.now() + 7*24*60*60*1000).toUTCString();
                    documents.cookie = `fakeRefreshToken=${token}; expires=${expires}; path=/`;

                    return token;
                    }

                    function getRefreshToken(){
                    return (documents.cookie.split(';').find(x => x.includes('fakeRefreshToken')) || '=').split('=') [1];
                    }
             }
        }    
        
        export let fakeBackendProvider ={
        
        provide: HTTP_INTERCEPTORS,
        useClass:FakeBackendInterceptor,
        multi:true
        };