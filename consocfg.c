/*
 * sercfg.c - the serial-port specific parts of the PuTTY
 * configuration box. Centralised as cross-platform code because
 * more than one platform will want to use it, but not part of the
 * main configuration. The expectation is that each platform's
 * local config function will call out to ser_setup_config_box() if
 * it needs to set up the standard serial stuff. (Of course, it can
 * then apply local tweaks after ser_setup_config_box() returns, if
 * it needs to.)
 */

#include <assert.h>
#include <stdlib.h>

#include "putty.h"
#include "dialog.h"
#include "storage.h"

void console_setup_config_box(struct controlbox *b, int midsession,
			  int parity_mask, int flow_mask)
{
    #if 0
    struct controlset *s;
    union control *c;

    if (!midsession) {
        int i;
        extern void config_protocolbuttons_handler(union control *, void *, void *, int);

        /*
        * Add the serial back end to the protocols list at the
        * top of the config box.
        */
        s = ctrl_getset(b, "Session", "hostport",
                "Specify the destination you want to connect to");

        for (i = 0; i < s->ncontrols; i++) {
            c = s->ctrls[i];
            if (c->generic.type == CTRL_RADIO &&
                    c->generic.handler == config_protocolbuttons_handler)
            {
                c->radio.nbuttons++;
                c->radio.ncolumns++;
                c->radio.buttons =
                    sresize(c->radio.buttons, c->radio.nbuttons, char *);
                c->radio.buttons[c->radio.nbuttons-1] = dupstr("Console");
                c->radio.buttondata =
                    sresize(c->radio.buttondata, c->radio.nbuttons, intorptr);
                c->radio.buttondata[c->radio.nbuttons-1] = I(PROT_CONSOLE);
                if (c->radio.shortcuts) {
                    c->radio.shortcuts =
                        sresize(c->radio.shortcuts, c->radio.nbuttons, char);
                    c->radio.shortcuts[c->radio.nbuttons-1] = NO_SHORTCUT;
                }
            }
        }
    }
    #endif
}
