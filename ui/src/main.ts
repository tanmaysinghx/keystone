import { bootstrapApplication } from '@angular/platform-browser';
import { provideHttpClient } from '@angular/common/http';
import { AppComponent } from './app';
bootstrapApplication(AppComponent, {providers:[provideHttpClient()]}).catch(console.error);
