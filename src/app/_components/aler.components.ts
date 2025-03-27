import { Component, OnInit, OnDestroy, Input } from '@angular/core';
import { Router, NavigationStart } from '@angular/router';
import { Subscription } from 'rxjs';

import { Alert, AlertType } from '@app/models';
import { AlertService } from '@app/services';

@Component({
    selector: 'alert',
    templateUrl: 'alert.component.html'
})
export class AlertComponent implements OnInit, OnDestroy {
    @Input() id = 'default-alert';
    @Input() fade = true;

    alerts: Alert[] = [];
    alertSubscription: Subscription;
    routerSubscription: Subscription;

    constructor(private router: Router, private alertService: AlertService) {}

    ngOnInit() {
        // subscribe to new alert notifications
        this.alertSubscription = this.alertService.onAlert(this.id).subscribe(alert => {
            if (!alert.message) {
                // clear alerts when an empty alert is received
                this.alerts = this.alerts.filter(x => x.keepAfterRouteChange);
                this.alerts.forEach(x => delete x.keepAfterRouteChange);
                return;
            }

            // add alert to array
            this.alerts.push(alert);

            // auto close alert if required
            if (alert.autoClose) {
                setTimeout(() => this.removeAlert(alert), 3000);
            }
        });

        // clear alerts on location change
        this.routerSubscription = this.router.events.subscribe(event => {
            if (event instanceof NavigationStart) {
                this.alertService.clear(this.id);
            }
        });
    }

    ngOnDestroy() {
        // unsubscribe to avoid memory leaks
        this.alertSubscription.unsubscribe();
        this.routerSubscription.unsubscribe();
    }

    removeAlert(alert: Alert) {
        if (!this.alerts.includes(alert)) return;

        if (this.fade) {
            // fade out alert
            const alertToFade = this.alerts.find(x => x === alert);
            if (alertToFade) {
                alertToFade.fade = true;
                setTimeout(() => {
                    this.alerts = this.alerts.filter(x => x !== alert);
                }, 250);
            }
        } else {
            this.alerts = this.alerts.filter(x => x !== alert);
        }
    }

    cssClasses(alert: Alert) {
        if (!alert) return '';

        const classes = ['alert', 'alert-dismissable'];

        const alertTypeClass = {
            [AlertType.Success]: 'alert-success',
            [AlertType.Error]: 'alert-danger',
            [AlertType.Info]: 'alert-info',
            [AlertType.Warning]: 'alert-warning'
        };

        classes.push(alertTypeClass[alert.type]);

        if (alert.fade) {
            classes.push('fade');
        }

        return classes.join(' ');
    }
}