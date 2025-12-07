
## User element

If you like to use any kind of user-login you have to start by creating a User element that is a child of `noapiframe.elements.UserBase`

In the most simble form this could look like this:

```python
from noapiframe.elements import UserBase


class User(UserBase):
    pass
```

But as with every other element you can add your own attributes and functions.  
The attributes `admin`, `login` and `pw` are already defined in `UserBase` and should not be overwritten, but can be used as every other attribute.

## Session element

Next go ahead and create a Session element, that is a child of `noapiframe.elements.SessionBase` and should at least look like the following:

```python
from noapiframe.elements import SessionBase
from .user import User


class Session(SessionBase):
    cookie_name = 'your-cookie-name'
    _user_cls = User
```

The attributes `till`, `ip`, `complete` and `user_id` are already defined in `SessionBase` and should not be overwritten.

## Login endpoint

now to be able to login, create an endpoint for that, noAPIframe brings all you need with `LoginEndpointBase`. Just create a child and set your Session element, like that:

```python
class LoginEndpoint(LoginEndpointBase):
    _session_cls = Session
```

On your frontend you need a corresponding service, to execute the login. Take an example on this Angular service:

```js
import { Injectable } from '@angular/core';
import { environment } from '../../environments/environment';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Observable, of } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { Login } from '../interfaces/login';
import { Md5 } from 'ts-md5';

@Injectable({
  providedIn: 'root'
})
export class LoginService {

  private loginUrl = environment.apiUrl + '/login/';

  constructor(private http: HttpClient) { }

  public getLogin(): Observable<Login> {
    return this.http.get<Login>(this.loginUrl, {withCredentials:true}).pipe(catchError(this.handleError));
  }

  public startLogin(username: string): Observable<Login> {
    return this.http.get<Login>(this.loginUrl + "?user=" + username, {withCredentials:true}).pipe(catchError(this.handleError));
  }

  public completeLogin(session_id: string, password: string): Observable<Login> {
    let md5 = new Md5();
    let pw = md5.appendStr(session_id).appendStr(password).end()
    return this.http.post<Login>(this.loginUrl, {'pw': pw}, {withCredentials:true}).pipe(catchError(this.handleError));
  }

  public logout(): Observable<any> {
    return this.http.put<any>(this.loginUrl, {}, {withCredentials:true}).pipe(catchError(this.handleError));
  }

  private handleError(error: HttpErrorResponse) {
    if (error.status === 0) {
      console.error('An error occurred:', error.error);
    } else {
      console.error(`Backend returned code ${error.status}, body was: `, error.error);
    }
    let login: Login = {};
    return of(login);
  }
}
```
