/*
 * LED support for the input layer
 *
 * Copyright 2010-2014 Samuel Thibault <samuel.thibault@ens-lyon.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/leds.h>
#include <linux/input.h>

/*
 * Keyboard LEDs are propagated by default like the following example:
 *
 * VT keyboard numlock trigger
 * -> vt::numl VT LED
 * -> vt-numl VT trigger
 * -> per-device inputX::numl LED
 *
 * Userland can however choose the trigger for the vt::numl LED, or
 * independently choose the trigger for any inputx::numl LED.
 *
 *
 * VT LED classes and triggers are registered on-demand according to
 * existing LED devices
 */

/* Handler for VT LEDs, just triggers the corresponding VT trigger. */
static void vt_led_set(struct led_classdev *cdev,
			  enum led_brightness brightness);
static struct led_classdev vt_leds[LED_CNT] = {
#define DEFINE_INPUT_LED(vt_led, nam, deftrig) \
	[vt_led] = { \
		.name = "vt::"nam, \
		.max_brightness = 1, \
		.brightness_set = vt_led_set, \
		.default_trigger = deftrig, \
	}
/* Default triggers for the VT LEDs just correspond to the legacy
 * usage. */
	DEFINE_INPUT_LED(LED_NUML, "numl", "kbd-numlock"),
	DEFINE_INPUT_LED(LED_CAPSL, "capsl", "kbd-capslock"),
	DEFINE_INPUT_LED(LED_SCROLLL, "scrolll", "kbd-scrollock"),
	DEFINE_INPUT_LED(LED_COMPOSE, "compose", NULL),
	DEFINE_INPUT_LED(LED_KANA, "kana", "kbd-kanalock"),
	DEFINE_INPUT_LED(LED_SLEEP, "sleep", NULL),
	DEFINE_INPUT_LED(LED_SUSPEND, "suspend", NULL),
	DEFINE_INPUT_LED(LED_MUTE, "mute", NULL),
	DEFINE_INPUT_LED(LED_MISC, "misc", NULL),
	DEFINE_INPUT_LED(LED_MAIL, "mail", NULL),
	DEFINE_INPUT_LED(LED_CHARGING, "charging", NULL),
};
static const char *const vt_led_names[LED_CNT] = {
	[LED_NUML] = "numl",
	[LED_CAPSL] = "capsl",
	[LED_SCROLLL] = "scrolll",
	[LED_COMPOSE] = "compose",
	[LED_KANA] = "kana",
	[LED_SLEEP] = "sleep",
	[LED_SUSPEND] = "suspend",
	[LED_MUTE] = "mute",
	[LED_MISC] = "misc",
	[LED_MAIL] = "mail",
	[LED_CHARGING] = "charging",
};
/* Handler for hotplug initialization */
static void vt_led_trigger_activate(struct led_classdev *cdev);
/* VT triggers */
static struct led_trigger vt_led_triggers[LED_CNT] = {
#define DEFINE_INPUT_LED_TRIGGER(vt_led, nam) \
	[vt_led] = { \
		.name = "vt-"nam, \
		.activate = vt_led_trigger_activate, \
	}
	DEFINE_INPUT_LED_TRIGGER(LED_NUML, "numl"),
	DEFINE_INPUT_LED_TRIGGER(LED_CAPSL, "capsl"),
	DEFINE_INPUT_LED_TRIGGER(LED_SCROLLL, "scrolll"),
	DEFINE_INPUT_LED_TRIGGER(LED_COMPOSE, "compose"),
	DEFINE_INPUT_LED_TRIGGER(LED_KANA, "kana"),
	DEFINE_INPUT_LED_TRIGGER(LED_SLEEP, "sleep"),
	DEFINE_INPUT_LED_TRIGGER(LED_SUSPEND, "suspend"),
	DEFINE_INPUT_LED_TRIGGER(LED_MUTE, "mute"),
	DEFINE_INPUT_LED_TRIGGER(LED_MISC, "misc"),
	DEFINE_INPUT_LED_TRIGGER(LED_MAIL, "mail"),
	DEFINE_INPUT_LED_TRIGGER(LED_CHARGING, "charging"),
};

/* Lock for registration coherency */
static DEFINE_MUTEX(vt_led_registered_lock);

/* Which VT LED classes and triggers are registered */
static unsigned long vt_led_registered[BITS_TO_LONGS(LED_CNT)];

/* Number of input devices having each LED */
static int vt_led_references[LED_CNT];

/* VT LED state change, tell the VT trigger.  */
static void vt_led_set(struct led_classdev *cdev,
			  enum led_brightness brightness)
{
	int led = cdev - vt_leds;

	led_trigger_event(&vt_led_triggers[led], !!brightness);
}

/* LED state change for some keyboard, notify that keyboard.  */
static void perdevice_input_led_set(struct led_classdev *cdev,
			  enum led_brightness brightness)
{
	struct input_dev *dev;
	struct led_classdev *leds;
	int led;

	dev = cdev->dev->platform_data;
	if (!dev)
		/* Still initializing */
		return;
	leds = dev->leds;
	led = cdev - leds;

	input_event(dev, EV_LED, led, !!brightness);
	input_event(dev, EV_SYN, SYN_REPORT, 0);
}

/* Keyboard hotplug, initialize its LED status */
static void vt_led_trigger_activate(struct led_classdev *cdev)
{
	struct led_trigger *trigger = cdev->trigger;
	int led = trigger - vt_led_triggers;

	if (cdev->brightness_set)
		cdev->brightness_set(cdev, vt_leds[led].brightness);
}

/* Free led stuff from input device, used at abortion and disconnection.  */
static void input_led_delete(struct input_dev *dev)
{
	if (dev) {
		struct led_classdev *leds = dev->leds;
		if (leds) {
			int i;
			for (i = 0; i < LED_CNT; i++)
				kfree(leds[i].name);
			kfree(leds);
			dev->leds = NULL;
		}
	}
}

/* A new input device with potential LEDs to connect.  */
int input_led_connect(struct input_dev *dev)
{
	int i, error = 0;
	struct led_classdev *leds;

	dev->leds = leds = kcalloc(LED_CNT, sizeof(*leds), GFP_KERNEL);
	if (!dev->leds)
		return -ENOMEM;

	/* lazily register missing VT LEDs */
	mutex_lock(&vt_led_registered_lock);
	for (i = 0; i < LED_CNT; i++)
		if (vt_leds[i].name && test_bit(i, dev->ledbit)) {
			if (!vt_led_references[i]) {
				led_trigger_register(&vt_led_triggers[i]);
				/* This keyboard is first to have led i,
				 * try to register it */
				if (!led_classdev_register(NULL, &vt_leds[i]))
					vt_led_references[i] = 1;
				else
					led_trigger_unregister(&vt_led_triggers[i]);
			} else
				vt_led_references[i]++;
		}
	mutex_unlock(&vt_led_registered_lock);

	/* and register this device's LEDs */
	for (i = 0; i < LED_CNT; i++)
		if (vt_leds[i].name && test_bit(i, dev->ledbit)) {
			leds[i].name = kasprintf(GFP_KERNEL, "%s::%s",
						dev_name(&dev->dev),
						vt_led_names[i]);
			if (!leds[i].name) {
				error = -ENOMEM;
				goto err;
			}
			leds[i].max_brightness = 1;
			leds[i].brightness_set = perdevice_input_led_set;
			leds[i].default_trigger = vt_led_triggers[i].name;
		}

	/* No issue so far, we can register for real.  */
	for (i = 0; i < LED_CNT; i++)
		if (leds[i].name) {
			led_classdev_register(&dev->dev, &leds[i]);
			leds[i].dev->platform_data = dev;
			perdevice_input_led_set(&leds[i],
					vt_leds[i].brightness);
		}

	return 0;

err:
	input_led_delete(dev);
	return error;
}

/*
 * Disconnected input device. Clean it, and deregister now-useless VT LEDs
 * and triggers.
 */
void input_led_disconnect(struct input_dev *dev)
{
	int i;
	struct led_classdev *leds = dev->leds;

	for (i = 0; i < LED_CNT; i++)
		if (leds[i].name)
			led_classdev_unregister(&leds[i]);

	input_led_delete(dev);

	mutex_lock(&vt_led_registered_lock);
	for (i = 0; i < LED_CNT; i++) {
		if (!vt_leds[i].name || !test_bit(i, dev->ledbit))
			continue;

		vt_led_references[i]--;
		if (vt_led_references[i]) {
			/* Still some devices needing it */
			continue;
		}

		led_classdev_unregister(&vt_leds[i]);
		led_trigger_unregister(&vt_led_triggers[i]);
		clear_bit(i, vt_led_registered);
	}
	mutex_unlock(&vt_led_registered_lock);
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("User LED support for input layer");
MODULE_AUTHOR("Samuel Thibault <samuel.thibault@ens-lyon.org>");
