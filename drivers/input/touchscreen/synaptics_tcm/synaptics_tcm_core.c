/*
 * Synaptics TCM touchscreen driver
 *
 * Copyright (C) 2017 Synaptics Incorporated. All rights reserved.
 *
 * Copyright (C) 2017 Scott Lin <scott.lin@tw.synaptics.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * INFORMATION CONTAINED IN THIS DOCUMENT IS PROVIDED "AS-IS," AND SYNAPTICS
 * EXPRESSLY DISCLAIMS ALL EXPRESS AND IMPLIED WARRANTIES, INCLUDING ANY
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE,
 * AND ANY WARRANTIES OF NON-INFRINGEMENT OF ANY INTELLECTUAL PROPERTY RIGHTS.
 * IN NO EVENT SHALL SYNAPTICS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, PUNITIVE, OR CONSEQUENTIAL DAMAGES ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OF THE INFORMATION CONTAINED IN THIS DOCUMENT, HOWEVER CAUSED
 * AND BASED ON ANY THEORY OF LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, AND EVEN IF SYNAPTICS WAS ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE. IF A TRIBUNAL OF COMPETENT JURISDICTION DOES
 * NOT PERMIT THE DISCLAIMER OF DIRECT DAMAGES OR ANY OTHER DAMAGES, SYNAPTICS'
 * TOTAL CUMULATIVE LIABILITY TO ANY PARTY SHALL NOT EXCEED ONE HUNDRED U.S.
 * DOLLARS.
 */

#include <linux/gpio.h>
#include <linux/kthread.h>
#include <linux/interrupt.h>
#include <linux/regulator/consumer.h>
#include <linux/completion.h>
#include <smartisan/hwstate.h>
#include "synaptics_tcm_core.h"
#include <linux/fb.h>
#include <linux/msm_drm_notify.h>

static int syna_tcm_resume(struct device *dev);
static struct syna_tcm_hcd *g_tcm_hcd;
static bool glove_mode = 0;

/* #define RESET_ON_RESUME */

#define RESET_ON_RESUME_DELAY_MS 20

#define TP_RESET_GPIO 80

#define PREDICTIVE_READING

#define MIN_READ_LENGTH 9

#define KEEP_DRIVER_ON_ERROR

#define FORCE_RUN_APPLICATION_FIRMWARE

#define NOTIFIER_PRIORITY 2

#define NOTIFIER_TIMEOUT_MS 500

#define RESPONSE_TIMEOUT_MS 3000

#define APP_STATUS_POLL_TIMEOUT_MS 1000

#define APP_STATUS_POLL_MS 100

#define ENABLE_IRQ_DELAY_MS 20

#define FALL_BACK_ON_POLLING

#define POLLING_WORK_DELAY_MS 5

#define RUN_WATCHDOG true

#define WATCHDOG_TRIGGER_COUNT 2

#define WATCHDOG_WORK_DELAY_MS 1000

#define MODE_SWITCH_DELAY_MS 100

#define READ_RETRY_US_MIN 5000

#define READ_RETRY_US_MAX 10000

DECLARE_COMPLETION(response_complete);

static ssize_t syna_tcm_sysfs_force_identify_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count);
static ssize_t syna_tcm_sysfs_force_identify_show(struct device *dev,
		struct device_attribute *attr, char *buf);

static ssize_t syna_tcm_sysfs_force_calibration_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count);
static ssize_t syna_tcm_sysfs_force_calibration_show(struct device *dev,
		struct device_attribute *attr, char *buf);

static ssize_t syna_tcm_sysfs_info_show(struct device *dev,
		struct device_attribute *attr, char *buf);

static ssize_t syna_tcm_sysfs_irq_en_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count);

static ssize_t syna_tcm_sysfs_prs_en_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count);
static ssize_t syna_tcm_sysfs_prs_en_show(struct device *dev,
		struct device_attribute *attr, char *buf);

static ssize_t syna_tcm_sysfs_reset_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count);

static ssize_t syna_tcm_sysfs_watchdog_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count);

static struct device_attribute attrs[] = {
	__ATTR(force_identify, (S_IRUGO | S_IWUSR | S_IWGRP),
			syna_tcm_sysfs_force_identify_show,
			syna_tcm_sysfs_force_identify_store),
	__ATTR(force_calibration, (S_IRUGO | S_IWUSR | S_IWGRP),
			syna_tcm_sysfs_force_calibration_show,
			syna_tcm_sysfs_force_calibration_store),
	__ATTR(info, S_IRUGO,
			syna_tcm_sysfs_info_show,
			syna_tcm_store_error),
	__ATTR(irq_en, (S_IWUSR | S_IWGRP),
			syna_tcm_show_error,
			syna_tcm_sysfs_irq_en_store),
	__ATTR(prs_en, (S_IRUGO | S_IWUSR | S_IWGRP),
			syna_tcm_sysfs_prs_en_show,
			syna_tcm_sysfs_prs_en_store),
	__ATTR(reset, (S_IWUSR | S_IWGRP),
			syna_tcm_show_error,
			syna_tcm_sysfs_reset_store),
	__ATTR(watchdog, (S_IWUSR | S_IWGRP),
			syna_tcm_show_error,
			syna_tcm_sysfs_watchdog_store),
};

static struct kobject *sysfs_dir;

static struct syna_tcm_module_pool mod_pool;

int syna_tcm_glove_switch(bool en)
{
	int retval = 0;
	retval = g_tcm_hcd->set_dynamic_config(g_tcm_hcd, DC_ENABLE_GLOVE, en);
	if (retval < 0) {
		LOGE(g_tcm_hcd->pdev->dev.parent,
				"Failed to switch glove mode, input = %d\n", en);
		goto exit;
	}
	if (en)
		glove_mode = 1;
	else
		glove_mode = 0;
	LOGI(g_tcm_hcd->pdev->dev.parent, "glove enable = %d\n", en);

exit:
	return retval;
}

static ssize_t syna_tcm_sysfs_force_identify_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	unsigned int input;
	struct device *p_dev;
	struct kobject *p_kobj;
	struct syna_tcm_hcd *tcm_hcd;

	p_kobj = sysfs_dir->parent;
	p_dev = container_of(p_kobj, struct device, kobj);
	tcm_hcd = dev_get_drvdata(p_dev);

	if (sscanf(buf, "%u", &input) != 1)
		return -EINVAL;

	LOGI(tcm_hcd->pdev->dev.parent, "input = %d\n", input);
	tcm_hcd->force_identify = !!input;
	tcm_hcd->need_wait_identify = false;

	return count;
}

#define TWENTY_SECOND 100
static ssize_t syna_tcm_sysfs_force_identify_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int retval;
	unsigned int wait_time = 0;
	struct device *p_dev;
	struct kobject *p_kobj;
	struct syna_tcm_hcd *tcm_hcd;

	p_kobj = sysfs_dir->parent;
	p_dev = container_of(p_kobj, struct device, kobj);
	tcm_hcd = dev_get_drvdata(p_dev);

	while (tcm_hcd->need_wait_identify && wait_time < TWENTY_SECOND) {
		LOGI(tcm_hcd->pdev->dev.parent, "waiting force identify result...\n");
		msleep(200);
		wait_time++;
	}

	tcm_hcd->need_wait_identify = true;
	retval = snprintf(buf, PAGE_SIZE, "%d", wait_time < TWENTY_SECOND ? tcm_hcd->force_identify : -1);

	return retval;
}

static ssize_t syna_tcm_sysfs_force_calibration_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	unsigned int input;
	struct device *p_dev;
	struct kobject *p_kobj;
	struct syna_tcm_hcd *tcm_hcd;

	p_kobj = sysfs_dir->parent;
	p_dev = container_of(p_kobj, struct device, kobj);
	tcm_hcd = dev_get_drvdata(p_dev);

	if (sscanf(buf, "%u", &input) != 1)
		return -EINVAL;

	LOGI(tcm_hcd->pdev->dev.parent, "input = %d\n", input);
	tcm_hcd->force_calibration = !!input;
	tcm_hcd->need_wait_calibration = false;

	return count;
}

static ssize_t syna_tcm_sysfs_force_calibration_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int retval;
	unsigned int wait_time = 0;
	struct device *p_dev;
	struct kobject *p_kobj;
	struct syna_tcm_hcd *tcm_hcd;

	p_kobj = sysfs_dir->parent;
	p_dev = container_of(p_kobj, struct device, kobj);
	tcm_hcd = dev_get_drvdata(p_dev);

	while (tcm_hcd->need_wait_calibration && wait_time < TWENTY_SECOND) {
		LOGI(tcm_hcd->pdev->dev.parent, "waiting force calibration result...\n");
		msleep(200);
		wait_time++;
	}

	tcm_hcd->need_wait_calibration = true;
	retval = snprintf(buf, PAGE_SIZE, "%d", wait_time < TWENTY_SECOND ? tcm_hcd->force_calibration : -1);


	return retval;
}

static ssize_t syna_tcm_sysfs_info_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int retval;
	unsigned int count;
	struct device *p_dev;
	struct kobject *p_kobj;
	struct syna_tcm_hcd *tcm_hcd;

	p_kobj = sysfs_dir->parent;
	p_dev = container_of(p_kobj, struct device, kobj);
	tcm_hcd = dev_get_drvdata(p_dev);

	mutex_lock(&tcm_hcd->extif_mutex);

	retval = tcm_hcd->identify(tcm_hcd, true);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to do identification\n");
		goto exit;
	}

	count = 0;

	retval = snprintf(buf, PAGE_SIZE - count,
			"TouchComm version:  %d\n",
			tcm_hcd->id_info.version);
	buf += retval;
	count += retval;

	retval = snprintf(buf, PAGE_SIZE - count,
			"Driver version:     %d.%d\n",
			(unsigned char)(SYNAPTICS_TCM_ID_VERSION >> 8),
			(unsigned char)SYNAPTICS_TCM_ID_VERSION);
	buf += retval;
	count += retval;

	switch (tcm_hcd->id_info.mode) {
	case MODE_APPLICATION:
		retval = snprintf(buf, PAGE_SIZE - count,
				"Firmware mode:      Application\n");
		break;
	case MODE_BOOTLOADER:
		retval = snprintf(buf, PAGE_SIZE - count,
				"Firmware mode:      Bootloader\n");
		break;
	case MODE_TDDI_BOOTLOADER:
		retval = snprintf(buf, PAGE_SIZE - count,
				"Firmware mode:      TDDI Bootloader\n");
		break;
	default:
		retval = snprintf(buf, PAGE_SIZE - count,
				"Firmware mode:      Unknown (%d)\n",
				tcm_hcd->id_info.mode);
		break;
	}
	buf += retval;
	count += retval;

	retval = snprintf(buf, PAGE_SIZE - count,
			"Part number:        ");
	buf += retval;
	count += retval;

	retval = secure_memcpy(buf,
			PAGE_SIZE - count,
			tcm_hcd->id_info.part_number,
			sizeof(tcm_hcd->id_info.part_number),
			sizeof(tcm_hcd->id_info.part_number));
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to copy part number string\n");
		goto exit;
	}
	buf += sizeof(tcm_hcd->id_info.part_number);
	count += sizeof(tcm_hcd->id_info.part_number);

	retval = snprintf(buf, PAGE_SIZE - count,
			"\n");
	buf += retval;
	count += retval;

	retval = snprintf(buf, PAGE_SIZE - count,
			"Packrat number:     %d\n",
			tcm_hcd->packrat_number);
	count += retval;

	retval = count;

exit:
	mutex_unlock(&tcm_hcd->extif_mutex);

	return retval;
}

static ssize_t syna_tcm_sysfs_irq_en_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	int retval;
	unsigned int input;
	struct device *p_dev;
	struct kobject *p_kobj;
	struct syna_tcm_hcd *tcm_hcd;

	p_kobj = sysfs_dir->parent;
	p_dev = container_of(p_kobj, struct device, kobj);
	tcm_hcd = dev_get_drvdata(p_dev);

	if (sscanf(buf, "%u", &input) != 1)
		return -EINVAL;

	mutex_lock(&tcm_hcd->extif_mutex);

	if (input == 0) {
		retval = tcm_hcd->enable_irq(tcm_hcd, false, true);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to disable interrupt\n");
			goto exit;
		}
	} else if (input == 1) {
		retval = tcm_hcd->enable_irq(tcm_hcd, true, NULL);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to enable interrupt\n");
			goto exit;
		}
	} else {
		retval = -EINVAL;
		goto exit;
	}

	retval = count;

exit:
	mutex_unlock(&tcm_hcd->extif_mutex);

	return retval;
}

extern bool need_report_pressure;
static ssize_t syna_tcm_sysfs_prs_en_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	unsigned int input;
	int retval;
	unsigned char *resp_buf;
	unsigned int resp_buf_size;
	unsigned int resp_length;

	struct device *p_dev;
	struct kobject *p_kobj;
	struct syna_tcm_hcd *tcm_hcd;
	p_kobj = sysfs_dir->parent;
	p_dev = container_of(p_kobj, struct device, kobj);
	tcm_hcd = dev_get_drvdata(p_dev);
	resp_buf = NULL;
	if (sscanf(buf, "%u", &input) != 1)
		return -EINVAL;

	/* need_report_pressure = !!input; */
	if (input) {
		retval = tcm_hcd->write_message(tcm_hcd,
				CMD_ENABLE_FORCE,
				NULL,
				0,
				&resp_buf,
				&resp_buf_size,
				&resp_length,
				NULL,
				0);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to write command %s\n",
					STR(CMD_ENABLE_FORCE));
		}
	}
	else {
		retval = tcm_hcd->write_message(tcm_hcd,
				CMD_DISABLE_FORCE,
				NULL,
				0,
				&resp_buf,
				&resp_buf_size,
				&resp_length,
				NULL,
				0);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to write command %s\n",
					STR(CMD_DISABLE_FORCE));
		}
	}
	kfree(resp_buf);
	return count;
}

static ssize_t syna_tcm_sysfs_prs_en_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", need_report_pressure);
}
static ssize_t syna_tcm_sysfs_reset_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	int retval;
	bool hw_reset;
	unsigned int input;
	struct device *p_dev;
	struct kobject *p_kobj;
	struct syna_tcm_hcd *tcm_hcd;

	p_kobj = sysfs_dir->parent;
	p_dev = container_of(p_kobj, struct device, kobj);
	tcm_hcd = dev_get_drvdata(p_dev);

	if (sscanf(buf, "%u", &input) != 1)
		return -EINVAL;

	if (input == 1)
		hw_reset = false;
	else if (input == 2)
		hw_reset = true;
	else
		return -EINVAL;

	mutex_lock(&tcm_hcd->extif_mutex);

	retval = tcm_hcd->reset(tcm_hcd, hw_reset, true);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to do reset\n");
		goto exit;
	}

	retval = count;

exit:
	mutex_unlock(&tcm_hcd->extif_mutex);

	return retval;
}

static ssize_t syna_tcm_sysfs_watchdog_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	unsigned int input;
	struct device *p_dev;
	struct kobject *p_kobj;
	struct syna_tcm_hcd *tcm_hcd;

	p_kobj = sysfs_dir->parent;
	p_dev = container_of(p_kobj, struct device, kobj);
	tcm_hcd = dev_get_drvdata(p_dev);

	if (sscanf(buf, "%u", &input) != 1)
		return -EINVAL;

	if (input != 0 && input != 1)
		return -EINVAL;

	mutex_lock(&tcm_hcd->extif_mutex);

	tcm_hcd->watchdog.run = input;
	tcm_hcd->update_watchdog(tcm_hcd, input);

	mutex_unlock(&tcm_hcd->extif_mutex);

	return count;
}

int syna_tcm_add_module(struct syna_tcm_module_cb *mod_cb, bool insert)
{
	struct syna_tcm_module_handler *mod_handler;

	if (!mod_pool.initialized) {
		mutex_init(&mod_pool.mutex);
		INIT_LIST_HEAD(&mod_pool.list);
		mod_pool.initialized = true;
	}

	mutex_lock(&mod_pool.mutex);

	if (insert) {
		mod_handler = kzalloc(sizeof(*mod_handler), GFP_KERNEL);
		if (!mod_handler) {
			pr_err("%s: Failed to allocate memory for mod_handler\n",
					__func__);
			mutex_unlock(&mod_pool.mutex);
			return -ENOMEM;
		}
		mod_handler->mod_cb = mod_cb;
		mod_handler->insert = true;
		mod_handler->detach = false;
		list_add_tail(&mod_handler->link, &mod_pool.list);
	} else if (!list_empty(&mod_pool.list)) {
		list_for_each_entry(mod_handler, &mod_pool.list, link) {
			if (mod_handler->mod_cb->type == mod_cb->type) {
				mod_handler->insert = false;
				mod_handler->detach = true;
				goto exit;
			}
		}
	}

exit:
	mutex_unlock(&mod_pool.mutex);

	if (mod_pool.queue_work)
		queue_work(mod_pool.workqueue, &mod_pool.work);

	return 0;
}
EXPORT_SYMBOL(syna_tcm_add_module);

static void syna_tcm_module_work(struct work_struct *work)
{
	struct syna_tcm_module_handler *mod_handler;
	struct syna_tcm_module_handler *tmp_handler;
	struct syna_tcm_hcd *tcm_hcd = mod_pool.tcm_hcd;

	mutex_lock(&mod_pool.mutex);

	if (!list_empty(&mod_pool.list)) {
		list_for_each_entry_safe(mod_handler,
				tmp_handler,
				&mod_pool.list,
				link) {
			if (mod_handler->insert) {
				if (mod_handler->mod_cb->init)
					mod_handler->mod_cb->init(tcm_hcd);
				mod_handler->insert = false;
			}
			if (mod_handler->detach) {
				if (mod_handler->mod_cb->remove)
					mod_handler->mod_cb->remove(tcm_hcd);
				list_del(&mod_handler->link);
				kfree(mod_handler);
			}
		}
	}

	mutex_unlock(&mod_pool.mutex);

	return;
}

/**
 * syna_tcm_report_notifier() - notify occurrence of report received from device
 *
 * @data: handle of core module
 *
 * The occurrence of the report generated by the device is forwarded to the
 * asynchronous inbox of each registered application module.
 */
static int syna_tcm_report_notifier(void *data)
{
	struct sched_param param = { .sched_priority = NOTIFIER_PRIORITY };
	struct syna_tcm_module_handler *mod_handler;
	struct syna_tcm_hcd *tcm_hcd = data;

	sched_setscheduler(current, SCHED_RR, &param);

	set_current_state(TASK_INTERRUPTIBLE);

	while (!kthread_should_stop()) {
		schedule();

		if (kthread_should_stop())
			break;

		set_current_state(TASK_RUNNING);

		mutex_lock(&mod_pool.mutex);

		if (!list_empty(&mod_pool.list)) {
			list_for_each_entry(mod_handler, &mod_pool.list, link) {
				if (!mod_handler->insert &&
						!mod_handler->detach &&
						(mod_handler->mod_cb->asyncbox))
					mod_handler->mod_cb->asyncbox(tcm_hcd);
			}
		}

		mutex_unlock(&mod_pool.mutex);

		set_current_state(TASK_INTERRUPTIBLE);
	};

	return 0;
}

/**
 * syna_tcm_dispatch_report() - dispatch report received from device
 *
 * @tcm_hcd: handle of core module
 *
 * The report generated by the device is forwarded to the synchronous inbox of
 * each registered application module for further processing. In addition, the
 * report notifier thread is woken up for asynchronous notification of the
 * report occurrence.
 */
static void syna_tcm_dispatch_report(struct syna_tcm_hcd *tcm_hcd)
{
	struct syna_tcm_module_handler *mod_handler;

	if (mutex_is_locked(&mod_pool.mutex))
		return;

	LOCK_BUFFER(tcm_hcd->in);
	LOCK_BUFFER(tcm_hcd->report.buffer);

	tcm_hcd->report.buffer.buf = &tcm_hcd->in.buf[MESSAGE_HEADER_SIZE];

	tcm_hcd->report.buffer.buf_size = tcm_hcd->in.buf_size;
	tcm_hcd->report.buffer.buf_size -= MESSAGE_HEADER_SIZE;

	tcm_hcd->report.buffer.data_length = tcm_hcd->payload_length;

	tcm_hcd->report.id = tcm_hcd->status_report_code;

	mutex_lock(&mod_pool.mutex);

	if (!list_empty(&mod_pool.list)) {
		list_for_each_entry(mod_handler, &mod_pool.list, link) {
			if (!mod_handler->insert &&
					!mod_handler->detach &&
					(mod_handler->mod_cb->syncbox))
				mod_handler->mod_cb->syncbox(tcm_hcd);
		}
	}

	mutex_unlock(&mod_pool.mutex);

	UNLOCK_BUFFER(tcm_hcd->report.buffer);
	UNLOCK_BUFFER(tcm_hcd->in);

	wake_up_process(tcm_hcd->notifier_thread);

	return;
}

/**
 * syna_tcm_dispatch_response() - dispatch response received from device
 *
 * @tcm_hcd: handle of core module
 *
 * The response to a command is forwarded to the sender of the command.
 */
static void syna_tcm_dispatch_response(struct syna_tcm_hcd *tcm_hcd)
{
	int retval;

	if (atomic_read(&tcm_hcd->command_status) != CMD_BUSY)
		return;

	tcm_hcd->response_code = tcm_hcd->status_report_code;

	if (tcm_hcd->payload_length == 0) {
		/* UNLOCK_BUFFER(tcm_hcd->resp); */
		atomic_set(&tcm_hcd->command_status, CMD_IDLE);
		goto exit;
	}
	LOCK_BUFFER(tcm_hcd->resp);

	retval = syna_tcm_alloc_mem(tcm_hcd,
			&tcm_hcd->resp,
			tcm_hcd->payload_length);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to allocate memory for tcm_hcd->resp.buf\n");
		UNLOCK_BUFFER(tcm_hcd->resp);
		atomic_set(&tcm_hcd->command_status, CMD_ERROR);
		goto exit;
	}

	LOCK_BUFFER(tcm_hcd->in);

	retval = secure_memcpy(tcm_hcd->resp.buf,
			tcm_hcd->resp.buf_size,
			&tcm_hcd->in.buf[MESSAGE_HEADER_SIZE],
			tcm_hcd->in.buf_size - MESSAGE_HEADER_SIZE,
			tcm_hcd->payload_length);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to copy payload\n");
		UNLOCK_BUFFER(tcm_hcd->in);
		UNLOCK_BUFFER(tcm_hcd->resp);
		atomic_set(&tcm_hcd->command_status, CMD_ERROR);
		goto exit;
	}

	tcm_hcd->resp.data_length = tcm_hcd->payload_length;

	UNLOCK_BUFFER(tcm_hcd->in);
	UNLOCK_BUFFER(tcm_hcd->resp);

	atomic_set(&tcm_hcd->command_status, CMD_IDLE);

exit:
	complete(&response_complete);

	return;
}

/**
 * syna_tcm_dispatch_message() - dispatch message received from device
 *
 * @tcm_hcd: handle of core module
 *
 * The information received in the message read in from the device is dispatched
 * to the appropriate destination based on whether the information represents a
 * report or a response to a command.
 */
static void syna_tcm_dispatch_message(struct syna_tcm_hcd *tcm_hcd)
{
	int retval;
	unsigned char *build_id;
	unsigned int payload_length;
	unsigned int max_write_size;

	if (tcm_hcd->status_report_code == REPORT_IDENTIFY) {
		payload_length = tcm_hcd->payload_length;

		LOCK_BUFFER(tcm_hcd->in);

		retval = secure_memcpy((unsigned char *)&tcm_hcd->id_info,
				sizeof(tcm_hcd->id_info),
				&tcm_hcd->in.buf[MESSAGE_HEADER_SIZE],
				tcm_hcd->in.buf_size - MESSAGE_HEADER_SIZE,
				MIN(sizeof(tcm_hcd->id_info), payload_length));
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to copy identification info\n");
			UNLOCK_BUFFER(tcm_hcd->in);
			return;
		}

		UNLOCK_BUFFER(tcm_hcd->in);

		build_id = tcm_hcd->id_info.build_id;
		tcm_hcd->packrat_number = le4_to_uint(build_id);

		max_write_size = le2_to_uint(tcm_hcd->id_info.max_write_size);
		tcm_hcd->wr_chunk_size = MIN(max_write_size, WR_CHUNK_SIZE);
		if (tcm_hcd->wr_chunk_size == 0)
			tcm_hcd->wr_chunk_size = max_write_size;

		LOGN(tcm_hcd->pdev->dev.parent,
				"Received identify report (firmware mode = 0x%02x)\n",
				tcm_hcd->id_info.mode);

		if (tcm_hcd->id_info.mode != MODE_APPLICATION) {
			LOGN(tcm_hcd->pdev->dev.parent,
					"Boot status = 0x%02x\n",
					tcm_hcd->boot_info.status);
		}

#ifdef FORCE_RUN_APPLICATION_FIRMWARE
		if (tcm_hcd->id_info.mode != MODE_APPLICATION &&
				!mutex_is_locked(&tcm_hcd->reset_mutex)) {
			if (atomic_read(&tcm_hcd->helper.task) == HELP_NONE) {
				atomic_set(&tcm_hcd->helper.task,
						HELP_RUN_APPLICATION_FIRMWARE);
				queue_work(tcm_hcd->helper.workqueue,
						&tcm_hcd->helper.work);
				return;
			}
		}
#endif

		if (atomic_read(&tcm_hcd->command_status) == CMD_BUSY) {
			switch (tcm_hcd->command) {
			case CMD_RESET:
			case CMD_RUN_BOOTLOADER_FIRMWARE:
			case CMD_RUN_APPLICATION_FIRMWARE:
				tcm_hcd->response_code = STATUS_OK;
				atomic_set(&tcm_hcd->command_status, CMD_IDLE);
				complete(&response_complete);
				break;
			default:
				LOGN(tcm_hcd->pdev->dev.parent,
						"Device has been reset\n");
				atomic_set(&tcm_hcd->command_status, CMD_ERROR);
				complete(&response_complete);
				break;
			}
		}
	}

	if (tcm_hcd->status_report_code >= REPORT_IDENTIFY)
		syna_tcm_dispatch_report(tcm_hcd);
	else
		syna_tcm_dispatch_response(tcm_hcd);

	return;
}

/**
 * syna_tcm_continued_read() - retrieve entire payload from device
 *
 * @tcm_hcd: handle of core module
 *
 * Read transactions are carried out until the entire payload is retrieved from
 * the device and stored in the handle of the core module.
 */
static int syna_tcm_continued_read(struct syna_tcm_hcd *tcm_hcd)
{
	int retval;
	unsigned char marker;
	unsigned char code;
	unsigned int idx;
	unsigned int offset;
	unsigned int chunks;
	unsigned int chunk_space;
	unsigned int xfer_length;
	unsigned int total_length;
	unsigned int remaining_length;

	total_length = MESSAGE_HEADER_SIZE + tcm_hcd->payload_length + 1;

	remaining_length = total_length - tcm_hcd->read_length;

	LOCK_BUFFER(tcm_hcd->in);

	retval = syna_tcm_realloc_mem(tcm_hcd,
			&tcm_hcd->in,
			total_length+1);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to reallocate memory for tcm_hcd->in.buf\n");
		UNLOCK_BUFFER(tcm_hcd->in);
		return retval;
	}

	/* available chunk space for payload = total chunk size minus header
	 * marker byte and header code byte */
	if (tcm_hcd->rd_chunk_size == 0)
		chunk_space = remaining_length;
	else
		chunk_space = tcm_hcd->rd_chunk_size - 2;

	chunks = ceil_div(remaining_length, chunk_space);

	chunks = chunks == 0 ? 1 : chunks;

	offset = tcm_hcd->read_length;

	LOCK_BUFFER(tcm_hcd->temp);

	for (idx = 0; idx < chunks; idx++) {
		if (remaining_length > chunk_space)
			xfer_length = chunk_space;
		else
			xfer_length = remaining_length;

		if (xfer_length == 1) {
			tcm_hcd->in.buf[offset] = MESSAGE_PADDING;
			offset += xfer_length;
			remaining_length -= xfer_length;
			continue;
		}

		retval = syna_tcm_alloc_mem(tcm_hcd,
				&tcm_hcd->temp,
				xfer_length + 2);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to allocate memory for tcm_hcd->temp.buf\n");
			UNLOCK_BUFFER(tcm_hcd->temp);
			UNLOCK_BUFFER(tcm_hcd->in);
			return retval;
		}

		retval = syna_tcm_read(tcm_hcd,
				tcm_hcd->temp.buf,
				xfer_length + 2);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to read from device\n");
			UNLOCK_BUFFER(tcm_hcd->temp);
			UNLOCK_BUFFER(tcm_hcd->in);
			return retval;
		}

		marker = tcm_hcd->temp.buf[0];
		code = tcm_hcd->temp.buf[1];

		if (marker != MESSAGE_MARKER) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Incorrect header marker (0x%02x)\n",
					marker);
			UNLOCK_BUFFER(tcm_hcd->temp);
			UNLOCK_BUFFER(tcm_hcd->in);
			return -EIO;
		}

		if (code != STATUS_CONTINUED_READ) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Incorrect header code (0x%02x)\n",
					code);
			UNLOCK_BUFFER(tcm_hcd->temp);
			UNLOCK_BUFFER(tcm_hcd->in);
			return -EIO;
		}

		retval = secure_memcpy(&tcm_hcd->in.buf[offset],
				total_length - offset,
				&tcm_hcd->temp.buf[2],
				xfer_length,
				xfer_length);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to copy payload\n");
			UNLOCK_BUFFER(tcm_hcd->temp);
			UNLOCK_BUFFER(tcm_hcd->in);
			return retval;
		}

		offset += xfer_length;

		remaining_length -= xfer_length;
	}

	UNLOCK_BUFFER(tcm_hcd->temp);
	UNLOCK_BUFFER(tcm_hcd->in);

	return 0;
}

/**
 * syna_tcm_raw_read() - retrieve specific number of data bytes from device
 *
 * @tcm_hcd: handle of core module
 * @in_buf: buffer for storing data retrieved from device
 * @length: number of bytes to retrieve from device
 *
 * Read transactions are carried out until the specific number of data bytes are
 * retrieved from the device and stored in in_buf.
 */
static int syna_tcm_raw_read(struct syna_tcm_hcd *tcm_hcd,
		unsigned char *in_buf, unsigned int length)
{
	int retval;
	unsigned char code;
	unsigned int idx;
	unsigned int offset;
	unsigned int chunks;
	unsigned int chunk_space;
	unsigned int xfer_length;
	unsigned int remaining_length;

	if (length < 2) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Invalid length information\n");
		return -EINVAL;
	}

	/* minus header marker byte and header code byte */
	remaining_length = length - 2;

	/* available chunk space for data = total chunk size minus header marker
	 * byte and header code byte */
	if (tcm_hcd->rd_chunk_size == 0)
		chunk_space = remaining_length;
	else
		chunk_space = tcm_hcd->rd_chunk_size - 2;

	chunks = ceil_div(remaining_length, chunk_space);

	chunks = chunks == 0 ? 1 : chunks;

	offset = 0;

	LOCK_BUFFER(tcm_hcd->temp);

	for (idx = 0; idx < chunks; idx++) {
		if (remaining_length > chunk_space)
			xfer_length = chunk_space;
		else
			xfer_length = remaining_length;

		if (xfer_length == 1) {
			in_buf[offset] = MESSAGE_PADDING;
			offset += xfer_length;
			remaining_length -= xfer_length;
			continue;
		}

		retval = syna_tcm_alloc_mem(tcm_hcd,
				&tcm_hcd->temp,
				xfer_length + 2);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to allocate memory for tcm_hcd->temp.buf\n");
			UNLOCK_BUFFER(tcm_hcd->temp);
			return retval;
		}

		retval = syna_tcm_read(tcm_hcd,
				tcm_hcd->temp.buf,
				xfer_length + 2);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to read from device\n");
			UNLOCK_BUFFER(tcm_hcd->temp);
			return retval;
		}

		code = tcm_hcd->temp.buf[1];

		if (idx == 0) {
			retval = secure_memcpy(&in_buf[0],
					length,
					&tcm_hcd->temp.buf[0],
					xfer_length + 2,
					xfer_length + 2);
		} else {
			if (code != STATUS_CONTINUED_READ) {
				LOGE(tcm_hcd->pdev->dev.parent,
						"Incorrect header code (0x%02x)\n",
						code);
				UNLOCK_BUFFER(tcm_hcd->temp);
				return -EIO;
			}

			retval = secure_memcpy(&in_buf[offset],
					length - offset,
					&tcm_hcd->temp.buf[2],
					xfer_length,
					xfer_length);
		}
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to copy data\n");
			UNLOCK_BUFFER(tcm_hcd->temp);
			return retval;
		}

		if (idx == 0)
			offset += (xfer_length + 2);
		else
			offset += xfer_length;

		remaining_length -= xfer_length;
	}

	UNLOCK_BUFFER(tcm_hcd->temp);

	return 0;
}

/**
 * syna_tcm_raw_write() - write command/data to device without receiving
 * response
 *
 * @tcm_hcd: handle of core module
 * @command: command to send to device
 * @data: data to send to device
 * @length: length of data in bytes
 *
 * A command and its data, if any, are sent to the device.
 */
static int syna_tcm_raw_write(struct syna_tcm_hcd *tcm_hcd,
		unsigned char command, unsigned char *data, unsigned int length)
{
	int retval;
	unsigned int idx;
	unsigned int chunks;
	unsigned int chunk_space;
	unsigned int xfer_length;
	unsigned int remaining_length;

	remaining_length = length;

	/* available chunk space for data = total chunk size minus command
	 * byte */
	if (tcm_hcd->wr_chunk_size == 0)
		chunk_space = remaining_length;
	else
		chunk_space = tcm_hcd->wr_chunk_size - 1;

	chunks = ceil_div(remaining_length, chunk_space);

	chunks = chunks == 0 ? 1 : chunks;

	LOCK_BUFFER(tcm_hcd->out);

	for (idx = 0; idx < chunks; idx++) {
		if (remaining_length > chunk_space)
			xfer_length = chunk_space;
		else
			xfer_length = remaining_length;

		retval = syna_tcm_alloc_mem(tcm_hcd,
				&tcm_hcd->out,
				xfer_length + 1);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to allocate memory for tcm_hcd->out.buf\n");
			UNLOCK_BUFFER(tcm_hcd->out);
			return retval;
		}

		if (idx == 0)
			tcm_hcd->out.buf[0] = command;
		else
			tcm_hcd->out.buf[0] = CMD_CONTINUE_WRITE;

		if (xfer_length) {
			retval = secure_memcpy(&tcm_hcd->out.buf[1],
					xfer_length,
					&data[idx * chunk_space],
					remaining_length,
					xfer_length);
			if (retval < 0) {
				LOGE(tcm_hcd->pdev->dev.parent,
						"Failed to copy data\n");
				UNLOCK_BUFFER(tcm_hcd->out);
				return retval;
			}
		}

		retval = syna_tcm_write(tcm_hcd,
				tcm_hcd->out.buf,
				xfer_length + 1);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to write to device\n");
			UNLOCK_BUFFER(tcm_hcd->out);
			return retval;
		}

		remaining_length -= xfer_length;
	}

	UNLOCK_BUFFER(tcm_hcd->out);

	return 0;
}

/**
 * syna_tcm_read_message() - read message from device
 *
 * @tcm_hcd: handle of core module
 * @in_buf: buffer for storing data in raw read mode
 * @length: length of data in bytes in raw read mode
 *
 * If in_buf is not NULL, raw read mode is used and syna_tcm_raw_read() is
 * called. Otherwise, a message including its entire payload is retrieved from
 * the device and dispatched to the appropriate destination.
 */
static int syna_tcm_read_message(struct syna_tcm_hcd *tcm_hcd,
		unsigned char *in_buf, unsigned int length)
{
	int retval;
	bool retry;
	unsigned int total_length;
	struct syna_tcm_message_header *header;

	mutex_lock(&tcm_hcd->rw_ctrl_mutex);

	if (in_buf != NULL) {
		retval = syna_tcm_raw_read(tcm_hcd, in_buf, length);
		goto exit;
	}

	retry = true;

retry:
	LOCK_BUFFER(tcm_hcd->in);
	//pr_err("%s:*****************read message begin*****\n", __func__);
	retval = syna_tcm_read(tcm_hcd,
			tcm_hcd->in.buf,
			tcm_hcd->read_length);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to read from device\n");
		UNLOCK_BUFFER(tcm_hcd->in);
		if (retry) {
			usleep_range(READ_RETRY_US_MIN, READ_RETRY_US_MAX);
			retry = false;
			goto retry;
		}
		goto exit;
	}

	header = (struct syna_tcm_message_header *)tcm_hcd->in.buf;

	if (header->marker != MESSAGE_MARKER) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Incorrect header marker (0x%02x)\n",
					header->marker);
			UNLOCK_BUFFER(tcm_hcd->in);
			retval = -ENXIO;
			if (retry) {
				usleep_range(READ_RETRY_US_MIN, READ_RETRY_US_MAX);
				retry = false;
				goto retry;
			}
		goto exit;
	}

	tcm_hcd->status_report_code = header->code;

	tcm_hcd->payload_length = le2_to_uint(header->length);

	LOGD(tcm_hcd->pdev->dev.parent,
			"Header code = 0x%02x\n",
			tcm_hcd->status_report_code);

	LOGD(tcm_hcd->pdev->dev.parent,
			"Payload length = %d\n",
			tcm_hcd->payload_length);

	if (tcm_hcd->status_report_code <= STATUS_ERROR ||
			tcm_hcd->status_report_code == STATUS_INVALID) {
		switch (tcm_hcd->status_report_code) {
		case STATUS_OK:
			break;
		case STATUS_CONTINUED_READ:
			LOGD(tcm_hcd->pdev->dev.parent,
					"Out-of-sync continued read\n");
		case STATUS_IDLE:
		case STATUS_BUSY:
			tcm_hcd->payload_length = 0;
			UNLOCK_BUFFER(tcm_hcd->in);
			retval = 0;
			goto exit;
		default:
			LOGE(tcm_hcd->pdev->dev.parent,
					"Incorrect header code (0x%02x)\n",
					tcm_hcd->status_report_code);
			if (tcm_hcd->status_report_code == STATUS_INVALID) {
				tcm_hcd->payload_length = 0;
			}
		}
	}

	total_length = MESSAGE_HEADER_SIZE + tcm_hcd->payload_length + 1;

#ifdef PREDICTIVE_READING
	if (total_length <= tcm_hcd->read_length) {
		goto check_padding;
	} else if (total_length - 1 == tcm_hcd->read_length) {
		tcm_hcd->in.buf[total_length - 1] = MESSAGE_PADDING;
		goto check_padding;
	}
#else
	if (tcm_hcd->payload_length == 0) {
		tcm_hcd->in.buf[total_length - 1] = MESSAGE_PADDING;
		goto check_padding;
	}
#endif

	UNLOCK_BUFFER(tcm_hcd->in);

	retval = syna_tcm_continued_read(tcm_hcd);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to do continued read\n");
		goto exit;
	};

	LOCK_BUFFER(tcm_hcd->in);

	tcm_hcd->in.buf[0] = MESSAGE_MARKER;
	tcm_hcd->in.buf[1] = tcm_hcd->status_report_code;
	tcm_hcd->in.buf[2] = (unsigned char)tcm_hcd->payload_length;
	tcm_hcd->in.buf[3] = (unsigned char)(tcm_hcd->payload_length >> 8);

check_padding:
	if (tcm_hcd->in.buf[total_length - 1] != MESSAGE_PADDING) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Incorrect message padding byte (0x%02x)\n",
				tcm_hcd->in.buf[total_length - 1]);
		UNLOCK_BUFFER(tcm_hcd->in);
		retval = -EIO;
		goto exit;
	}

	UNLOCK_BUFFER(tcm_hcd->in);

#ifdef PREDICTIVE_READING
	total_length = MAX(total_length, MIN_READ_LENGTH);
	tcm_hcd->read_length = MIN(total_length, tcm_hcd->rd_chunk_size);
	if (tcm_hcd->rd_chunk_size == 0)
		tcm_hcd->read_length = total_length;
#endif

	syna_tcm_dispatch_message(tcm_hcd);

	retval = 0;
exit:
	if (retval < 0) {
		if (atomic_read(&tcm_hcd->command_status) == CMD_BUSY) {
			atomic_set(&tcm_hcd->command_status, CMD_ERROR);
			complete(&response_complete);
		}
	}

	mutex_unlock(&tcm_hcd->rw_ctrl_mutex);

	return retval;
}

/**
 * syna_tcm_write_message() - write message to device and receive response
 *
 * @tcm_hcd: handle of core module
 * @command: command to send to device
 * @payload: payload of command
 * @length: length of payload in bytes
 * @resp_buf: buffer for storing command response
 * @resp_buf_size: size of response buffer in bytes
 * @resp_length: length of command response in bytes
 * @polling_delay_ms: delay time after sending command before resuming polling
 *
 * If resp_buf is NULL, raw write mode is used and syna_tcm_raw_write() is
 * called. Otherwise, a command and its payload, if any, are sent to the device
 * and the response to the command generated by the device is read in.
 */
static int syna_tcm_write_message(struct syna_tcm_hcd *tcm_hcd,
		unsigned char command, unsigned char *payload,
		unsigned int length, unsigned char **resp_buf,
		unsigned int *resp_buf_size, unsigned int *resp_length,
		unsigned char *response_code, unsigned int polling_delay_ms)
{
	int retval;
	unsigned int idx;
	unsigned int chunks;
	unsigned int chunk_space;
	unsigned int xfer_length;
	unsigned int remaining_length;
	unsigned int command_status;

	command_status = 0;
	if (response_code != NULL)
		*response_code = STATUS_INVALID;

	if (!tcm_hcd->do_polling && current->pid == tcm_hcd->isr_pid) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Invalid execution context\n");
		return -EINVAL;
	}

	mutex_lock(&tcm_hcd->command_mutex);

	mutex_lock(&tcm_hcd->rw_ctrl_mutex);

	if (resp_buf == NULL) {
		retval = syna_tcm_raw_write(tcm_hcd, command, payload, length);
		mutex_unlock(&tcm_hcd->rw_ctrl_mutex);
		goto exit;
	}

	if (tcm_hcd->do_polling && polling_delay_ms) {
		cancel_delayed_work_sync(&tcm_hcd->polling_work);
		flush_workqueue(tcm_hcd->polling_workqueue);
	}

	atomic_set(&tcm_hcd->command_status, CMD_BUSY);

	//INIT_COMPLETION(response_complete);
	reinit_completion(&response_complete);
	tcm_hcd->command = command;

	LOCK_BUFFER(tcm_hcd->resp);

	tcm_hcd->resp.buf = *resp_buf;
	tcm_hcd->resp.buf_size = *resp_buf_size;
	tcm_hcd->resp.data_length = 0;

	UNLOCK_BUFFER(tcm_hcd->resp);

	/* adding two length bytes as part of payload */
	remaining_length = length + 2;

	/* available chunk space for payload = total chunk size minus command
	 * byte */
	if (tcm_hcd->wr_chunk_size == 0)
		chunk_space = remaining_length;
	else
		chunk_space = tcm_hcd->wr_chunk_size - 1;

	chunks = ceil_div(remaining_length, chunk_space);

	chunks = chunks == 0 ? 1 : chunks;

	LOGD(tcm_hcd->pdev->dev.parent,
			"Command = 0x%02x\n",
			command);

	LOCK_BUFFER(tcm_hcd->out);

	for (idx = 0; idx < chunks; idx++) {
		if (remaining_length > chunk_space)
			xfer_length = chunk_space;
		else
			xfer_length = remaining_length;

		retval = syna_tcm_alloc_mem(tcm_hcd,
				&tcm_hcd->out,
				xfer_length + 1);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to allocate memory for tcm_hcd->out.buf\n");
			UNLOCK_BUFFER(tcm_hcd->out);
			mutex_unlock(&tcm_hcd->rw_ctrl_mutex);
			goto exit;
		}

		if (idx == 0) {
			tcm_hcd->out.buf[0] = command;
			tcm_hcd->out.buf[1] = (unsigned char)length;
			tcm_hcd->out.buf[2] = (unsigned char)(length >> 8);

			if (xfer_length > 2) {
				retval = secure_memcpy(&tcm_hcd->out.buf[3],
						xfer_length - 2,
						payload,
						remaining_length - 2,
						xfer_length - 2);
				if (retval < 0) {
					LOGE(tcm_hcd->pdev->dev.parent,
							"Failed to copy payload\n");
					UNLOCK_BUFFER(tcm_hcd->out);
					mutex_unlock(&tcm_hcd->rw_ctrl_mutex);
					goto exit;
				}
			}
		} else {
			tcm_hcd->out.buf[0] = CMD_CONTINUE_WRITE;

			retval = secure_memcpy(&tcm_hcd->out.buf[1],
					xfer_length,
					&payload[idx * chunk_space - 2],
					remaining_length,
					xfer_length);
			if (retval < 0) {
				LOGE(tcm_hcd->pdev->dev.parent,
						"Failed to copy payload\n");
				UNLOCK_BUFFER(tcm_hcd->out);
				mutex_unlock(&tcm_hcd->rw_ctrl_mutex);
				goto exit;
			}
		}

		retval = syna_tcm_write(tcm_hcd,
				tcm_hcd->out.buf,
				xfer_length + 1);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to write to device\n");
			UNLOCK_BUFFER(tcm_hcd->out);
			mutex_unlock(&tcm_hcd->rw_ctrl_mutex);
			goto exit;
		}

		remaining_length -= xfer_length;
	}

	UNLOCK_BUFFER(tcm_hcd->out);

	mutex_unlock(&tcm_hcd->rw_ctrl_mutex);

	if (tcm_hcd->do_polling && polling_delay_ms) {
		queue_delayed_work(tcm_hcd->polling_workqueue,
				&tcm_hcd->polling_work,
				msecs_to_jiffies(polling_delay_ms));
	}

	retval = wait_for_completion_timeout(&response_complete,
			msecs_to_jiffies(RESPONSE_TIMEOUT_MS));
	if (retval == 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Timed out waiting for response (command 0x%02x)\n",
				tcm_hcd->command);
		retval = -EIO;
		goto exit;
	}
	command_status = atomic_read(&tcm_hcd->command_status);
	if (command_status != CMD_IDLE) {
		LOGE(tcm_hcd->pdev->dev.parent,
			"Failed to get valid response  (command 0x%02x)\n", tcm_hcd->command);
		retval = -EIO;
		goto exit;
	}
	LOCK_BUFFER(tcm_hcd->resp);
	if (tcm_hcd->response_code != STATUS_OK) {
		if (tcm_hcd->resp.data_length) {
			LOGE(tcm_hcd->pdev->dev.parent,
				"Error code = 0x%02x (command 0x%02x)\n", tcm_hcd->resp.buf[0], tcm_hcd->command);\
		}
		retval = -EIO;
	} else {
		retval = 0;
	}
	*resp_buf = tcm_hcd->resp.buf;
	*resp_buf_size = tcm_hcd->resp.buf_size;
	*resp_length = tcm_hcd->resp.data_length;

	if (response_code != NULL)
		*response_code = tcm_hcd->response_code;

	UNLOCK_BUFFER(tcm_hcd->resp);
exit:
	tcm_hcd->command = CMD_NONE;

	atomic_set(&tcm_hcd->command_status, CMD_IDLE);

	mutex_unlock(&tcm_hcd->command_mutex);

	return retval;
}

static void syna_tcm_check_hdl(struct syna_tcm_hcd *tcm_hcd)
{
	struct syna_tcm_module_handler *mod_handler;

	if (mutex_is_locked(&mod_pool.mutex))
		return;

	mutex_lock(&mod_pool.mutex);

	tcm_hcd->status_report_code = REPORT_HDL;

	if (!list_empty(&mod_pool.list)) {
		list_for_each_entry(mod_handler, &mod_pool.list, link) {
			if (!mod_handler->insert &&
					!mod_handler->detach &&
					(mod_handler->mod_cb->syncbox))
				mod_handler->mod_cb->syncbox(tcm_hcd);
		}
	}

	mutex_unlock(&mod_pool.mutex);

	return;
}

static void syna_tcm_update_watchdog(struct syna_tcm_hcd *tcm_hcd, bool en)
{
	cancel_delayed_work_sync(&tcm_hcd->watchdog.work);
	flush_workqueue(tcm_hcd->watchdog.workqueue);

	if (!tcm_hcd->watchdog.run) {
		tcm_hcd->watchdog.count = 0;
		return;
	}

	if (en) {
		queue_delayed_work(tcm_hcd->watchdog.workqueue,
				&tcm_hcd->watchdog.work,
				msecs_to_jiffies(WATCHDOG_WORK_DELAY_MS));
	} else {
		tcm_hcd->watchdog.count = 0;
	}

	return;
}

static void syna_tcm_watchdog_work(struct work_struct *work)
{
	int retval;
	unsigned char marker;
	struct delayed_work *delayed_work =
			container_of(work, struct delayed_work, work);
	struct syna_tcm_watchdog *watchdog =
			container_of(delayed_work, struct syna_tcm_watchdog,
			work);
	struct syna_tcm_hcd *tcm_hcd =
			container_of(watchdog, struct syna_tcm_hcd, watchdog);

	if (mutex_is_locked(&tcm_hcd->rw_ctrl_mutex))
		goto exit;

	mutex_lock(&tcm_hcd->rw_ctrl_mutex);

	retval = syna_tcm_read(tcm_hcd,
			&marker,
			1);

	mutex_unlock(&tcm_hcd->rw_ctrl_mutex);

	if (retval < 0 || marker != MESSAGE_MARKER) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to read from device\n");

		tcm_hcd->watchdog.count++;

		if (tcm_hcd->watchdog.count >= WATCHDOG_TRIGGER_COUNT) {
			retval = tcm_hcd->reset(tcm_hcd, true, false);
			if (retval < 0) {
				LOGE(tcm_hcd->pdev->dev.parent,
						"Failed to do reset\n");
			}
			tcm_hcd->watchdog.count = 0;
		}
	}

exit:
	queue_delayed_work(tcm_hcd->watchdog.workqueue,
			&tcm_hcd->watchdog.work,
			msecs_to_jiffies(WATCHDOG_WORK_DELAY_MS));

	return;
}

static void syna_tcm_polling_work(struct work_struct *work)
{
	int retval;
	struct delayed_work *delayed_work =
			container_of(work, struct delayed_work, work);
	struct syna_tcm_hcd *tcm_hcd =
			container_of(delayed_work, struct syna_tcm_hcd,
			polling_work);

	if (!tcm_hcd->do_polling)
		return;

	retval = tcm_hcd->read_message(tcm_hcd,
			NULL,
			0);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to read message\n");
	}

	if (!(tcm_hcd->in_suspend && retval < 0)) {
		queue_delayed_work(tcm_hcd->polling_workqueue,
				&tcm_hcd->polling_work,
				msecs_to_jiffies(POLLING_WORK_DELAY_MS));
	}

	return;
}

static irqreturn_t syna_tcm_isr(int irq, void *data)
{
	int retval;
	struct syna_tcm_hcd *tcm_hcd = data;
	const struct syna_tcm_board_data *bdata = tcm_hcd->hw_if->bdata;

	if (unlikely(gpio_get_value(bdata->irq_gpio) != bdata->irq_on_state))
		goto exit;

	tcm_hcd->isr_pid = current->pid;

	retval = tcm_hcd->read_message(tcm_hcd,
			NULL,
			0);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to read message\n");
		if (retval == -ENXIO && tcm_hcd->hw_if->bus_io->type == BUS_SPI)
			syna_tcm_check_hdl(tcm_hcd);
	}

exit:
	return IRQ_HANDLED;
}

static int syna_tcm_enable_irq(struct syna_tcm_hcd *tcm_hcd, bool en, bool ns)
{
	int retval;
	const struct syna_tcm_board_data *bdata = tcm_hcd->hw_if->bdata;
	static bool irq_freed = true;

	mutex_lock(&tcm_hcd->irq_en_mutex);

	if (en) {
		if (tcm_hcd->irq_enabled) {
			LOGD(tcm_hcd->pdev->dev.parent,
					"Interrupt already enabled\n");
			retval = 0;
			goto exit;
		}

		if (bdata->irq_gpio < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Invalid IRQ GPIO\n");
			retval = -EINVAL;
			goto queue_polling_work;
		}

		if (irq_freed) {
			retval = request_threaded_irq(tcm_hcd->irq, NULL,
					syna_tcm_isr, bdata->irq_flags,
					PLATFORM_DRIVER_NAME, tcm_hcd);
			if (retval < 0) {
				LOGE(tcm_hcd->pdev->dev.parent,
						"Failed to create interrupt thread\n");
			}
		} else {
			enable_irq(tcm_hcd->irq);
			retval = 0;
		}

queue_polling_work:
		if (retval < 0) {
#ifdef FALL_BACK_ON_POLLING
			queue_delayed_work(tcm_hcd->polling_workqueue,
					&tcm_hcd->polling_work,
					msecs_to_jiffies(POLLING_WORK_DELAY_MS));
			tcm_hcd->do_polling = true;
			retval = 0;
#endif
			goto exit;
		}
		if (retval < 0)
			goto exit;
		else
			msleep(ENABLE_IRQ_DELAY_MS);
	} else {
		if (!tcm_hcd->irq_enabled) {
			LOGD(tcm_hcd->pdev->dev.parent,
					"Interrupt already disabled\n");
			retval = 0;
			goto exit;
		}

		if (bdata->irq_gpio >= 0) {
			if (ns) {
				disable_irq_nosync(tcm_hcd->irq);
			} else {
				disable_irq(tcm_hcd->irq);
				free_irq(tcm_hcd->irq, tcm_hcd);
			}
			irq_freed = !ns;
		}
		if(ns) {
			cancel_delayed_work(&tcm_hcd->polling_work);
		} else {
			cancel_delayed_work_sync(&tcm_hcd->polling_work);
			flush_workqueue(tcm_hcd->polling_workqueue);
		}

		tcm_hcd->do_polling = false;
	}

	retval = 0;

exit:
	if (retval == 0)
		tcm_hcd->irq_enabled = en;

	mutex_unlock(&tcm_hcd->irq_en_mutex);

	return retval;
}

static int syna_tcm_set_gpio(struct syna_tcm_hcd *tcm_hcd, int gpio,
		bool config, int dir, int state)
{
	int retval;
	char label[16];

	if (config) {
		snprintf(label, 16, "tcm_gpio_%d\n", gpio);

		retval = gpio_request(gpio, label);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to request GPIO %d\n",
					gpio);
			return retval;
		}

		if (dir == 0)
			retval = gpio_direction_input(gpio);
		else
			retval = gpio_direction_output(gpio, state);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to set GPIO %d direction\n",
					gpio);
			return retval;
		}
	} else {
		gpio_free(gpio);
	}

	return 0;
}

static int syna_tcm_config_gpio(struct syna_tcm_hcd *tcm_hcd)
{
	int retval;
	const struct syna_tcm_board_data *bdata = tcm_hcd->hw_if->bdata;

	if (bdata->irq_gpio >= 0) {
		retval = syna_tcm_set_gpio(tcm_hcd, bdata->irq_gpio,
				true, 0, 0);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to configure interrupt GPIO\n");
			goto err_set_gpio_irq;
		}
	}

	if (bdata->power_gpio >= 0) {
		retval = syna_tcm_set_gpio(tcm_hcd, bdata->power_gpio,
				true, 1, !bdata->power_on_state);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to configure power GPIO\n");
			goto err_set_gpio_power;
		}
	}

	if (bdata->reset_gpio >= 0) {
		retval = syna_tcm_set_gpio(tcm_hcd, bdata->reset_gpio,
				true, 1, !bdata->reset_on_state);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to configure reset GPIO\n");
			goto err_set_gpio_reset;
		}
	}

	if (bdata->power_gpio >= 0) {
		gpio_set_value(bdata->power_gpio, bdata->power_on_state);
		msleep(bdata->power_delay_ms);
	}

	if (bdata->reset_gpio >= 0) {
		gpio_set_value(bdata->reset_gpio, bdata->reset_on_state);
		msleep(bdata->reset_active_ms);
		gpio_set_value(bdata->reset_gpio, !bdata->reset_on_state);
		msleep(bdata->reset_delay_ms);
	}

	return 0;

err_set_gpio_reset:
	if (bdata->power_gpio >= 0)
		syna_tcm_set_gpio(tcm_hcd, bdata->power_gpio, false, 0, 0);

err_set_gpio_power:
	if (bdata->irq_gpio >= 0)
		syna_tcm_set_gpio(tcm_hcd, bdata->irq_gpio, false, 0, 0);

err_set_gpio_irq:
	return retval;
}

static int syna_tcm_enable_regulator(struct syna_tcm_hcd *tcm_hcd, bool en)
{
	int retval;
	const struct syna_tcm_board_data *bdata = tcm_hcd->hw_if->bdata;

	if (!en) {
		retval = 0;
		goto disable_pwr_reg;
	}

	if (tcm_hcd->bus_reg) {
		retval = regulator_enable(tcm_hcd->bus_reg);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to enable bus regulator\n");
			goto exit;
		}
	}

	if (tcm_hcd->pwr_reg) {
		retval = regulator_enable(tcm_hcd->pwr_reg);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to enable power regulator\n");
			goto disable_bus_reg;
		}
		msleep(bdata->power_delay_ms);
	}

	return 0;

disable_pwr_reg:
	if (tcm_hcd->pwr_reg)
		regulator_disable(tcm_hcd->pwr_reg);

disable_bus_reg:
	if (tcm_hcd->bus_reg)
		regulator_disable(tcm_hcd->bus_reg);

exit:
	return retval;
}

static int syna_tcm_get_regulator(struct syna_tcm_hcd *tcm_hcd, bool get)
{
	int retval;
	const struct syna_tcm_board_data *bdata = tcm_hcd->hw_if->bdata;

	if (!get) {
		retval = 0;
		goto regulator_put;
	}

	if (bdata->bus_reg_name != NULL && *bdata->bus_reg_name != 0) {
		tcm_hcd->bus_reg = regulator_get(tcm_hcd->pdev->dev.parent,
				bdata->bus_reg_name);
		if (IS_ERR(tcm_hcd->bus_reg)) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to get bus regulator\n");
			retval = PTR_ERR(tcm_hcd->bus_reg);
			goto regulator_put;
		}
	}

	if (bdata->pwr_reg_name != NULL && *bdata->pwr_reg_name != 0) {
		tcm_hcd->pwr_reg = regulator_get(tcm_hcd->pdev->dev.parent,
				bdata->pwr_reg_name);
		if (IS_ERR(tcm_hcd->pwr_reg)) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to get power regulator\n");
			retval = PTR_ERR(tcm_hcd->pwr_reg);
			goto regulator_put;
		}
	}

	return 0;

regulator_put:
	if (tcm_hcd->bus_reg) {
		regulator_put(tcm_hcd->bus_reg);
		tcm_hcd->bus_reg = NULL;
	}

	if (tcm_hcd->pwr_reg) {
		regulator_put(tcm_hcd->pwr_reg);
		tcm_hcd->pwr_reg = NULL;
	}

	return retval;
}

static int syna_tcm_get_app_info(struct syna_tcm_hcd *tcm_hcd)
{
	int retval;
	unsigned char *resp_buf;
	unsigned int resp_buf_size;
	unsigned int resp_length;
	unsigned int timeout;

	timeout = APP_STATUS_POLL_TIMEOUT_MS;

	resp_buf = NULL;
	resp_buf_size = 0;

get_app_info:
	retval = tcm_hcd->write_message(tcm_hcd,
			CMD_GET_APPLICATION_INFO,
			NULL,
			0,
			&resp_buf,
			&resp_buf_size,
			&resp_length,
			NULL,
			0);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to write command %s\n",
				STR(CMD_GET_APPLICATION_INFO));
		goto exit;
	}

	retval = secure_memcpy((unsigned char *)&tcm_hcd->app_info,
			sizeof(tcm_hcd->app_info),
			resp_buf,
			resp_buf_size,
			MIN(sizeof(tcm_hcd->app_info), resp_length));
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to copy application info\n");
		goto exit;
	}

	tcm_hcd->app_status = le2_to_uint(tcm_hcd->app_info.status);

	if (tcm_hcd->app_status == APP_STATUS_BOOTING ||
			tcm_hcd->app_status == APP_STATUS_UPDATING) {
		if (timeout > 0) {
			msleep(APP_STATUS_POLL_MS);
			timeout -= APP_STATUS_POLL_MS;
			goto get_app_info;
		}
	}

	retval = 0;

exit:
	kfree(resp_buf);

	return retval;
}

static int syna_tcm_get_boot_info(struct syna_tcm_hcd *tcm_hcd)
{
	int retval;
	unsigned char *resp_buf;
	unsigned int resp_buf_size;
	unsigned int resp_length;

	resp_buf = NULL;
	resp_buf_size = 0;

	retval = tcm_hcd->write_message(tcm_hcd,
			CMD_GET_BOOT_INFO,
			NULL,
			0,
			&resp_buf,
			&resp_buf_size,
			&resp_length,
			NULL,
			0);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to write command %s\n",
				STR(CMD_GET_BOOT_INFO));
		goto exit;
	}

	retval = secure_memcpy((unsigned char *)&tcm_hcd->boot_info,
			sizeof(tcm_hcd->boot_info),
			resp_buf,
			resp_buf_size,
			MIN(sizeof(tcm_hcd->boot_info), resp_length));
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to copy boot info\n");
		goto exit;
	}

	retval = 0;

exit:
	kfree(resp_buf);

	return retval;
}

static int syna_tcm_identify(struct syna_tcm_hcd *tcm_hcd, bool id)
{
	int retval;
	unsigned char *resp_buf;
	unsigned int resp_buf_size;
	unsigned int resp_length;
	unsigned int max_write_size;

	resp_buf = NULL;
	resp_buf_size = 0;

	mutex_lock(&tcm_hcd->identify_mutex);

	if (!id)
		goto get_info;

	retval = tcm_hcd->write_message(tcm_hcd,
			CMD_IDENTIFY,
			NULL,
			0,
			&resp_buf,
			&resp_buf_size,
			&resp_length,
			NULL,
			0);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to write command %s\n",
				STR(CMD_IDENTIFY));
		goto exit;
	}

	retval = secure_memcpy((unsigned char *)&tcm_hcd->id_info,
			sizeof(tcm_hcd->id_info),
			resp_buf,
			resp_buf_size,
			MIN(sizeof(tcm_hcd->id_info), resp_length));
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to copy identification info\n");
		goto exit;
	}

	tcm_hcd->packrat_number = le4_to_uint(tcm_hcd->id_info.build_id);

	max_write_size = le2_to_uint(tcm_hcd->id_info.max_write_size);
	tcm_hcd->wr_chunk_size = MIN(max_write_size, WR_CHUNK_SIZE);
	if (tcm_hcd->wr_chunk_size == 0)
		tcm_hcd->wr_chunk_size = max_write_size;

get_info:
	switch (tcm_hcd->id_info.mode) {
	case MODE_APPLICATION:
		retval = syna_tcm_get_app_info(tcm_hcd);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to get application info\n");
			goto exit;
		}
	break;
	case MODE_BOOTLOADER:
	case MODE_TDDI_BOOTLOADER:
		retval = syna_tcm_get_boot_info(tcm_hcd);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to get boot info\n");
			goto exit;
		}
		break;
	default:
		break;
	}

	retval = 0;

exit:
	mutex_unlock(&tcm_hcd->identify_mutex);

	kfree(resp_buf);

	return retval;
}

static int syna_tcm_run_application_firmware(struct syna_tcm_hcd *tcm_hcd)
{
	int retval;
	bool retry;
	unsigned char *resp_buf;
	unsigned int resp_buf_size;
	unsigned int resp_length;

	retry = true;

	resp_buf = NULL;
	resp_buf_size = 0;

retry:
	retval = tcm_hcd->write_message(tcm_hcd,
			CMD_RUN_APPLICATION_FIRMWARE,
			NULL,
			0,
			&resp_buf,
			&resp_buf_size,
			&resp_length,
			NULL,
			MODE_SWITCH_DELAY_MS);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to write command %s\n",
				STR(CMD_RUN_APPLICATION_FIRMWARE));
		goto exit;
	}

	retval = tcm_hcd->identify(tcm_hcd, false);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to do identification\n");
		goto exit;
	}

	if (tcm_hcd->id_info.mode != MODE_APPLICATION) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to run application firmware (boot status = 0x%02x)\n",
				tcm_hcd->boot_info.status);
		if (retry) {
			retry = false;
			goto retry;
		}
		retval = -EINVAL;
		goto exit;
	} else if (tcm_hcd->app_status != APP_STATUS_OK) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Application status = 0x%02x\n",
				tcm_hcd->app_status);
	}

	retval = 0;

exit:
	kfree(resp_buf);

	return retval;
}

static int syna_tcm_run_bootloader_firmware(struct syna_tcm_hcd *tcm_hcd)
{
	int retval;
	unsigned char *resp_buf;
	unsigned int resp_buf_size;
	unsigned int resp_length;

	resp_buf = NULL;
	resp_buf_size = 0;

	retval = tcm_hcd->write_message(tcm_hcd,
			CMD_RUN_BOOTLOADER_FIRMWARE,
			NULL,
			0,
			&resp_buf,
			&resp_buf_size,
			&resp_length,
			NULL,
			MODE_SWITCH_DELAY_MS);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to write command %s\n",
				STR(CMD_RUN_BOOTLOADER_FIRMWARE));
		goto exit;
	}

	retval = tcm_hcd->identify(tcm_hcd, false);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to do identification\n");
		goto exit;
	}

	if (tcm_hcd->id_info.mode == MODE_APPLICATION) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to enter bootloader mode\n");
		retval = -EINVAL;
		goto exit;
	}

	retval = 0;

exit:
	kfree(resp_buf);

	return retval;
}

static int syna_tcm_switch_mode(struct syna_tcm_hcd *tcm_hcd,
		enum firmware_mode mode)
{
	int retval;

	mutex_lock(&tcm_hcd->reset_mutex);

	tcm_hcd->update_watchdog(tcm_hcd, false);

	switch (mode) {
	case FW_MODE_BOOTLOADER:
		retval = syna_tcm_run_bootloader_firmware(tcm_hcd);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to switch to bootloader mode\n");
			goto exit;
		}
		break;
	case FW_MODE_APPLICATION:
		retval = syna_tcm_run_application_firmware(tcm_hcd);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to switch to application mode\n");
			goto exit;
		}
		break;
	default:
		LOGE(tcm_hcd->pdev->dev.parent,
				"Invalid firmware mode\n");
		retval = -EINVAL;
		goto exit;
	}

	retval = 0;

exit:
	tcm_hcd->update_watchdog(tcm_hcd, true);

	mutex_unlock(&tcm_hcd->reset_mutex);

	return retval;
}

static int syna_tcm_set_dynamic_config(struct syna_tcm_hcd *tcm_hcd,
		enum dynamic_config_id id, unsigned short value)
{
	int retval;
	unsigned char out_buf[3];
	unsigned char *resp_buf;
	unsigned int resp_buf_size;
	unsigned int resp_length;

	resp_buf = NULL;
	resp_buf_size = 0;

	out_buf[0] = (unsigned char)id;
	out_buf[1] = (unsigned char)value;
	out_buf[2] = (unsigned char)(value >> 8);

	retval = tcm_hcd->write_message(tcm_hcd,
			CMD_SET_DYNAMIC_CONFIG,
			out_buf,
			sizeof(out_buf),
			&resp_buf,
			&resp_buf_size,
			&resp_length,
			NULL,
			0);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to write command %s\n",
				STR(CMD_SET_DYNAMIC_CONFIG));
		goto exit;
	}

	retval = 0;

exit:
	kfree(resp_buf);

	return retval;
}

static int syna_tcm_sleep(struct syna_tcm_hcd *tcm_hcd, bool en)
{
	int retval;
	unsigned char command;
	unsigned char *resp_buf;
	unsigned int resp_buf_size;
	unsigned int resp_length;

	command = en ? CMD_ENTER_DEEP_SLEEP : CMD_EXIT_DEEP_SLEEP;

	resp_buf = NULL;
	resp_buf_size = 0;

	retval = tcm_hcd->write_message(tcm_hcd,
			command,
			NULL,
			0,
			&resp_buf,
			&resp_buf_size,
			&resp_length,
			NULL,
			0);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to write command %s\n",
				en ?
				STR(CMD_ENTER_DEEP_SLEEP) :
				STR(CMD_EXIT_DEEP_SLEEP));
		goto exit;
	}

	retval = 0;

exit:
	kfree(resp_buf);

	return retval;
}

static int syna_tcm_reset(struct syna_tcm_hcd *tcm_hcd, bool hw, bool update_wd)
{
	int retval;
	unsigned char *resp_buf;
	unsigned int resp_buf_size;
	unsigned int resp_length;
	struct syna_tcm_module_handler *mod_handler;
	const struct syna_tcm_board_data *bdata = tcm_hcd->hw_if->bdata;

	resp_buf = NULL;
	resp_buf_size = 0;

	mutex_lock(&tcm_hcd->reset_mutex);
	if (update_wd)
		tcm_hcd->update_watchdog(tcm_hcd, false);

	if (hw) {
		/*
		 * if (bdata->reset_gpio < 0) {
		 *         LOGE(tcm_hcd->pdev->dev.parent,
		 *                         "Hardware reset unavailable\n");
		 *         retval = -EINVAL;
		 *         goto exit;
		 * }
		 */
		printk("<syna> start to hardware tp reset\n");
		gpio_set_value(TP_RESET_GPIO, 0);
		msleep(10);
		gpio_set_value(TP_RESET_GPIO, 1);
	} else {
		retval = tcm_hcd->write_message(tcm_hcd,
				CMD_RESET,
				NULL,
				0,
				&resp_buf,
				&resp_buf_size,
				&resp_length,
				NULL,
				bdata->reset_delay_ms);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to write command %s\n",
					STR(CMD_RESET));
			goto exit;
		}
	}

	msleep(bdata->reset_delay_ms);

	retval = tcm_hcd->identify(tcm_hcd, false);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to do identification\n");
		goto exit;
	}

	if (tcm_hcd->id_info.mode == MODE_APPLICATION)
		goto dispatch_reset;

	retval = tcm_hcd->write_message(tcm_hcd,
			CMD_RUN_APPLICATION_FIRMWARE,
			NULL,
			0,
			&resp_buf,
			&resp_buf_size,
			&resp_length,
			NULL,
			MODE_SWITCH_DELAY_MS);
	if (retval < 0) {
		LOGN(tcm_hcd->pdev->dev.parent,
				"Failed to write command %s\n",
				STR(CMD_RUN_APPLICATION_FIRMWARE));
	}

	retval = tcm_hcd->identify(tcm_hcd, false);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to do identification\n");
		goto exit;
	}

dispatch_reset:
	LOGN(tcm_hcd->pdev->dev.parent,
			"Firmware mode = 0x%02x\n",
			tcm_hcd->id_info.mode);

	if (tcm_hcd->id_info.mode != MODE_APPLICATION) {
		LOGN(tcm_hcd->pdev->dev.parent,
				"Boot status = 0x%02x\n",
				tcm_hcd->boot_info.status);
	} else if (tcm_hcd->app_status != APP_STATUS_OK) {
		LOGN(tcm_hcd->pdev->dev.parent,
				"Application status = 0x%02x\n",
				tcm_hcd->app_status);
	}

	mutex_lock(&mod_pool.mutex);

	if (!list_empty(&mod_pool.list)) {
		list_for_each_entry(mod_handler, &mod_pool.list, link) {
			if (!mod_handler->insert &&
					!mod_handler->detach &&
					(mod_handler->mod_cb->reset))
				mod_handler->mod_cb->reset(tcm_hcd);
		}
	}

	mutex_unlock(&mod_pool.mutex);

	retval = 0;

exit:
	if (update_wd)
		tcm_hcd->update_watchdog(tcm_hcd, true);

	mutex_unlock(&tcm_hcd->reset_mutex);

	kfree(resp_buf);

	return retval;
}

static int syna_tcm_rezero(struct syna_tcm_hcd *tcm_hcd)
{
	int retval;
	unsigned char *resp_buf;
	unsigned int resp_buf_size;
	unsigned int resp_length;

	resp_buf = NULL;
	resp_buf_size = 0;

	retval = tcm_hcd->write_message(tcm_hcd,
			CMD_REZERO,
			NULL,
			0,
			&resp_buf,
			&resp_buf_size,
			&resp_length,
			NULL,
			0);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to write command %s\n",
				STR(CMD_REZERO));
		goto exit;
	}

	retval = 0;

exit:
	kfree(resp_buf);

	return retval;
}

static void syna_tcm_resume_work(struct work_struct *work)
{
	struct syna_tcm_hcd *tcm_hcd =
			container_of(work, struct syna_tcm_hcd,
			resume_work);
	printk("<syna> enter resume work.......\n");
	syna_tcm_resume(&tcm_hcd->pdev->dev);
	/* tcm_hcd->fb_ready = true; */
}
static void syna_tcm_helper_work(struct work_struct *work)
{
	int retval;
	unsigned char task;
	struct syna_tcm_module_handler *mod_handler;
	struct syna_tcm_helper *helper =
			container_of(work, struct syna_tcm_helper, work);
	struct syna_tcm_hcd *tcm_hcd =
			container_of(helper, struct syna_tcm_hcd, helper);

	task = atomic_read(&helper->task);

	switch (task) {
	case HELP_RUN_APPLICATION_FIRMWARE:
		mutex_lock(&tcm_hcd->reset_mutex);
		tcm_hcd->update_watchdog(tcm_hcd, false);
		retval = syna_tcm_run_application_firmware(tcm_hcd);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to switch to application mode\n");
		}
		tcm_hcd->update_watchdog(tcm_hcd, true);
		mutex_unlock(&tcm_hcd->reset_mutex);
		break;
	case HELP_SEND_RESET_NOTIFICATION:
		mutex_lock(&tcm_hcd->reset_mutex);
		retval = tcm_hcd->identify(tcm_hcd, true);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to do identification\n");
			mutex_unlock(&tcm_hcd->reset_mutex);
			break;
		}
		mutex_lock(&mod_pool.mutex);
		if (!list_empty(&mod_pool.list)) {
			list_for_each_entry(mod_handler, &mod_pool.list, link) {
				if (!mod_handler->insert &&
						!mod_handler->detach &&
						(mod_handler->mod_cb->reset))
					mod_handler->mod_cb->reset(tcm_hcd);
			}
		}
		mutex_unlock(&mod_pool.mutex);
		mutex_unlock(&tcm_hcd->reset_mutex);
		break;
	default:
		break;
	}

	atomic_set(&helper->task, HELP_NONE);

	return;
}

static int syna_tcm_resume(struct device *dev)
{
	int retval = 0;
	struct syna_tcm_module_handler *mod_handler;
	struct syna_tcm_hcd *tcm_hcd = dev_get_drvdata(dev);

	if (!tcm_hcd->in_suspend)
		return 0;

	if (tcm_hcd->ts_pinctrl) {
		retval = pinctrl_select_state(tcm_hcd->ts_pinctrl,
				tcm_hcd->pinctrl_state_active);
		if (retval < 0)
			LOGE(tcm_hcd->pdev->dev.parent, "Cannot get active pinctrl state\n");
	}

	tcm_hcd->enable_irq(tcm_hcd, true, NULL);
	tcm_hcd->update_watchdog(tcm_hcd, true);

#ifdef RESET_ON_RESUME
	msleep(RESET_ON_RESUME_DELAY_MS);
	goto do_reset;
#endif

	if (tcm_hcd->id_info.mode != MODE_APPLICATION ||
			tcm_hcd->app_status != APP_STATUS_OK) {
		LOGN(tcm_hcd->pdev->dev.parent,
				"Application firmware not running\n");
		goto do_reset;
	}

	retval = tcm_hcd->sleep(tcm_hcd, false);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to exit deep sleep\n");
		goto exit;
	}

	retval = syna_tcm_rezero(tcm_hcd);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to rezero\n");
		goto exit;
	}

	goto mod_resume;

do_reset:
	retval = tcm_hcd->reset(tcm_hcd, false, true);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to do reset\n");
		goto exit;
	}

	if (tcm_hcd->id_info.mode != MODE_APPLICATION ||
			tcm_hcd->app_status != APP_STATUS_OK) {
		LOGN(tcm_hcd->pdev->dev.parent,
				"Application firmware not running\n");
		retval = 0;
		goto exit;
	}

mod_resume:
	mutex_lock(&mod_pool.mutex);
	if (!list_empty(&mod_pool.list)) {
		list_for_each_entry(mod_handler, &mod_pool.list, link) {
			if (!mod_handler->insert &&
					!mod_handler->detach &&
					(mod_handler->mod_cb->resume))
				mod_handler->mod_cb->resume(tcm_hcd);
		}
	}
	mutex_unlock(&mod_pool.mutex);

	retval = 0;

exit:
	tcm_hcd->in_suspend = false;
	if (glove_mode)
		syna_tcm_glove_switch(1);
	else
		syna_tcm_glove_switch(0);

	return retval;
}

static int syna_tcm_suspend(struct device *dev)
{
	int retval;

	struct syna_tcm_module_handler *mod_handler;
	struct syna_tcm_hcd *tcm_hcd = dev_get_drvdata(dev);

	if (tcm_hcd->in_suspend)
		return 0;

	mutex_lock(&tcm_hcd->extif_mutex);
	/* printk("synap suspend in\n"); */
	tcm_hcd->update_watchdog(tcm_hcd, false);

	if (tcm_hcd->id_info.mode != MODE_APPLICATION ||
			tcm_hcd->app_status != APP_STATUS_OK) {
		LOGN(tcm_hcd->pdev->dev.parent,
				"Application firmware not running\n");
		retval = 0;
		goto exit;
	}

#ifndef WAKEUP_GESTURE
	retval = tcm_hcd->sleep(tcm_hcd, true);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to enter deep sleep\n");
		goto exit;
	}
#endif

	mutex_lock(&mod_pool.mutex);

	if (!list_empty(&mod_pool.list)) {
		list_for_each_entry(mod_handler, &mod_pool.list, link) {
			if (!mod_handler->insert &&
					!mod_handler->detach &&
					(mod_handler->mod_cb->suspend))
				mod_handler->mod_cb->suspend(tcm_hcd);
		}
	}

	mutex_unlock(&mod_pool.mutex);

	retval = 0;

exit:
	mutex_unlock(&tcm_hcd->extif_mutex);
#ifndef WAKEUP_GESTURE
	tcm_hcd->enable_irq(tcm_hcd, false, true);
#endif
	if (tcm_hcd->ts_pinctrl) {
		retval = pinctrl_select_state(tcm_hcd->ts_pinctrl,
				tcm_hcd->pinctrl_state_suspend);
		if (retval < 0)
			LOGE(tcm_hcd->pdev->dev.parent, "Cannot get suspend pinctrl state\n");
	}

	tcm_hcd->in_suspend = true;

	return retval;
}

#ifdef CONFIG_FB
extern bool touch_needed;
static int syna_tcm_fb_notifier_cb(struct notifier_block *nb,
		unsigned long action, void *data)
{
	int retval = 0;
	int *val = NULL;
	struct syna_tcm_hcd *tcm_hcd =
			container_of(nb, struct syna_tcm_hcd, fb_notifier);
	struct msm_drm_notifier *drm_data = (struct msm_drm_notifier *)data;

	if (tcm_hcd == NULL || tcm_hcd->pdev == NULL) {
		pr_err("%s invalid parameter\n", __func__);
		return -EINVAL;
	}

	if (drm_data != NULL && drm_data->data != NULL && touch_needed) {
		val = (int *)drm_data->data;
		if (*val == MSM_DRM_BLANK_POWERDOWN) {
			cancel_work_sync(&tcm_hcd->resume_work);
			flush_workqueue(tcm_hcd->resume_workqueue);
			retval = syna_tcm_suspend(&tcm_hcd->pdev->dev);
			tcm_hcd->fb_ready = false;
		} else if (*val == MSM_DRM_BLANK_UNBLANK) {
			tcm_hcd->fb_ready = true;
			queue_work(tcm_hcd->resume_workqueue,
					&tcm_hcd->resume_work);
		}

		touch_needed = false;
	}

	return retval;
}
#endif

#define PINCTRL_STATE_ACTIVE	"pmx_ts_active"
#define PINCTRL_STATE_SUSPEND	"pmx_ts_suspend"

extern int do_skip_serial;
#define GPIO4_5_SET "gpio4_5_set"
struct pinctrl_state *gpio4_5;

static int syna_tcm_pinctrl_init(struct syna_tcm_hcd *tcm_hcd, bool init)
{
	int retval = 0;

	if (!init)
		goto deinit_pinctrl;

	/* Get pinctrl if target uses pinctrl */
	tcm_hcd->ts_pinctrl = devm_pinctrl_get(tcm_hcd->pdev->dev.parent);
	if (IS_ERR_OR_NULL(tcm_hcd->ts_pinctrl)) {
		retval = PTR_ERR(tcm_hcd->ts_pinctrl);
		LOGE(tcm_hcd->pdev->dev.parent,
			"Target does not use pinctrl %d\n", retval);
		goto err_pinctrl_get;
	}

	tcm_hcd->pinctrl_state_active = pinctrl_lookup_state(tcm_hcd->ts_pinctrl,
				PINCTRL_STATE_ACTIVE);
	if (IS_ERR_OR_NULL(tcm_hcd->pinctrl_state_active)) {
		retval = PTR_ERR(tcm_hcd->pinctrl_state_active);
		LOGE(tcm_hcd->pdev->dev.parent,
			"Can not lookup %s pinstate %d\n",
			PINCTRL_STATE_ACTIVE, retval);
		goto err_pinctrl_lookup;
	}

	tcm_hcd->pinctrl_state_suspend
		= pinctrl_lookup_state(tcm_hcd->ts_pinctrl,
			PINCTRL_STATE_SUSPEND);
	if (IS_ERR_OR_NULL(tcm_hcd->pinctrl_state_suspend)) {
		retval = PTR_ERR(tcm_hcd->pinctrl_state_suspend);
		LOGE(tcm_hcd->pdev->dev.parent,
			"Can not lookup %s pinstate %d\n",
			PINCTRL_STATE_SUSPEND, retval);
		goto err_pinctrl_lookup;
	}

	printk("%s: do_skip_serial = %d\n", __func__, do_skip_serial);
	if(do_skip_serial) {
		gpio4_5=pinctrl_lookup_state(tcm_hcd->ts_pinctrl,GPIO4_5_SET);
		if(IS_ERR_OR_NULL(gpio4_5)){
			printk("%s:get gpio4_5 failed\n",__func__);
		}
		else{
		if(pinctrl_select_state(tcm_hcd->ts_pinctrl,gpio4_5)<0)
			printk("%s: set gpio4_5 state failed\n",__func__);
		}
	}
	return 0;

deinit_pinctrl:
	if (tcm_hcd->ts_pinctrl) {
		retval = pinctrl_select_state(tcm_hcd->ts_pinctrl,
				tcm_hcd->pinctrl_state_suspend);
		if (retval < 0)
			LOGE(tcm_hcd->pdev->dev.parent, "Cannot get suspend pinctrl state\n");
	} else {
		LOGE(tcm_hcd->pdev->dev.parent, "pinctrl is null, return\n");
		goto err_pinctrl_get;
	}
err_pinctrl_lookup:
	devm_pinctrl_put(tcm_hcd->ts_pinctrl);
err_pinctrl_get:
	tcm_hcd->ts_pinctrl = NULL;
	return retval;
}

extern int msm_drm_register_client(struct notifier_block *nb);
static int syna_tcm_probe(struct platform_device *pdev)
{
	int retval;
	int idx;
	unsigned char temp;
	struct syna_tcm_hcd *tcm_hcd;
	const struct syna_tcm_board_data *bdata;
	const struct syna_tcm_hw_interface *hw_if;

	printk("syna......rom-start\n");

	hw_if = pdev->dev.platform_data;
	if (!hw_if) {
		LOGE(&pdev->dev,
				"Hardware interface not found\n");
		return -ENODEV;
	}

	bdata = hw_if->bdata;
	if (!bdata) {
		LOGE(&pdev->dev,
				"Board data not found\n");
		return -ENODEV;
	}

	tcm_hcd = kzalloc(sizeof(*tcm_hcd), GFP_KERNEL);
	if (!tcm_hcd) {
		LOGE(&pdev->dev,
				"Failed to allocate memory for tcm_hcd\n");
		return -ENOMEM;
	}

	platform_set_drvdata(pdev, tcm_hcd);

	g_tcm_hcd = tcm_hcd;
	tcm_hcd->pdev = pdev;
	tcm_hcd->hw_if = hw_if;
	tcm_hcd->reset = syna_tcm_reset;
	tcm_hcd->sleep = syna_tcm_sleep;
	tcm_hcd->identify = syna_tcm_identify;
	tcm_hcd->enable_irq = syna_tcm_enable_irq;
	tcm_hcd->switch_mode = syna_tcm_switch_mode;
	tcm_hcd->read_message = syna_tcm_read_message;
	tcm_hcd->write_message = syna_tcm_write_message;
	tcm_hcd->set_dynamic_config = syna_tcm_set_dynamic_config;

	tcm_hcd->rd_chunk_size = RD_CHUNK_SIZE;
	tcm_hcd->wr_chunk_size = WR_CHUNK_SIZE;

#ifdef PREDICTIVE_READING
	tcm_hcd->read_length = MIN_READ_LENGTH;
#else
	tcm_hcd->read_length = MESSAGE_HEADER_SIZE;
#endif

	tcm_hcd->need_wait_calibration = true;
	tcm_hcd->need_wait_identify = true;

	tcm_hcd->watchdog.run = RUN_WATCHDOG;
	tcm_hcd->update_watchdog = syna_tcm_update_watchdog;

	if (bdata->irq_gpio >= 0)
		tcm_hcd->irq = gpio_to_irq(bdata->irq_gpio);
	else
		tcm_hcd->irq = bdata->irq_gpio;
	tcm_hcd->in_suspend = false;

	mutex_init(&tcm_hcd->extif_mutex);
	mutex_init(&tcm_hcd->reset_mutex);
	mutex_init(&tcm_hcd->irq_en_mutex);
	mutex_init(&tcm_hcd->io_ctrl_mutex);
	mutex_init(&tcm_hcd->rw_ctrl_mutex);
	mutex_init(&tcm_hcd->command_mutex);
	mutex_init(&tcm_hcd->identify_mutex);

	INIT_BUFFER(tcm_hcd->in, false);
	INIT_BUFFER(tcm_hcd->out, false);
	INIT_BUFFER(tcm_hcd->resp, true);
	INIT_BUFFER(tcm_hcd->temp, false);
	INIT_BUFFER(tcm_hcd->config, false);
	INIT_BUFFER(tcm_hcd->report.buffer, true);

	LOCK_BUFFER(tcm_hcd->in);

	retval = syna_tcm_alloc_mem(tcm_hcd,
			&tcm_hcd->in,
			tcm_hcd->read_length + 1);
	if (retval < 0) {
		LOGE(&pdev->dev,
				"Failed to allocate memory for tcm_hcd->in.buf\n");
		UNLOCK_BUFFER(tcm_hcd->in);
		goto err_alloc_mem;
	}

	UNLOCK_BUFFER(tcm_hcd->in);

	atomic_set(&tcm_hcd->command_status, CMD_IDLE);

	atomic_set(&tcm_hcd->helper.task, HELP_NONE);

	/*  wake_lock_init(&tcm_hcd->wakelock, WAKE_LOCK_SUSPEND, */
	/* PLATFORM_DRIVER_NAME); */


	if (!mod_pool.initialized) {
		mutex_init(&mod_pool.mutex);
		INIT_LIST_HEAD(&mod_pool.list);
		mod_pool.initialized = true;
	}

	retval = syna_tcm_get_regulator(tcm_hcd, true);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to get regulators\n");
		goto err_get_regulator;
	}

	retval = syna_tcm_enable_regulator(tcm_hcd, true);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to enable regulators\n");
		goto err_enable_regulator;
	}

	retval = syna_tcm_pinctrl_init(tcm_hcd, true);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to initalize pinctrl\n");
		goto err_pinctrl_init;
	} else {
		if (tcm_hcd->ts_pinctrl) {
			retval = pinctrl_select_state(tcm_hcd->ts_pinctrl,
					tcm_hcd->pinctrl_state_active);
			if (retval < 0)
				LOGE(tcm_hcd->pdev->dev.parent, "Cannot get active pinctrl state\n");
		}
	}
	retval = syna_tcm_config_gpio(tcm_hcd);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to configure GPIO's\n");
		goto err_config_gpio;
	}

	sysfs_dir = kobject_create_and_add(PLATFORM_DRIVER_NAME,
			&pdev->dev.kobj);
	if (!sysfs_dir) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to create sysfs directory\n");
		retval = -EINVAL;
		goto err_sysfs_create_dir;
	}

	tcm_hcd->sysfs_dir = sysfs_dir;

	for (idx = 0; idx < ARRAY_SIZE(attrs); idx++) {
		retval = sysfs_create_file(tcm_hcd->sysfs_dir,
				&attrs[idx].attr);
		if (retval < 0) {
			LOGE(tcm_hcd->pdev->dev.parent,
					"Failed to create sysfs file\n");
			goto err_sysfs_create_file;
		}
	}

#ifdef CONFIG_FB
	tcm_hcd->fb_notifier.notifier_call = syna_tcm_fb_notifier_cb;
	retval = msm_drm_register_client(&tcm_hcd->fb_notifier);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to register FB notifier client\n");
	}
#endif

	msleep(bdata->reset_delay_ms);

	retval = syna_tcm_read(tcm_hcd,
			&temp,
			1);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to read TCM marker\n");
	} else {
		LOGE(tcm_hcd->pdev->dev.parent,
				"TCM marker = 0x%02x\n", temp);
	}

	/*
	 * retval = syna_tcm_rmi_read(tcm_hcd,
	 *                 0x00ee,
	 *                 &temp,
	 *                 1);
	 * if (retval < 0) {
	 *         LOGE(tcm_hcd->pdev->dev.parent,
	 *                         "Failed to read RMI PDT\n");
	 * } else {
	 *         LOGE(tcm_hcd->pdev->dev.parent,
	 *                         "RMI function = 0x%02x\n", temp);
	 * }
	 */

	tcm_hcd->notifier_thread = kthread_run(syna_tcm_report_notifier,
			tcm_hcd, "syna_tcm_report_notifier");
	if (IS_ERR(tcm_hcd->notifier_thread)) {
		retval = PTR_ERR(tcm_hcd->notifier_thread);
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to create and run tcm_hcd->notifier_thread\n");
		goto err_create_run_kthread;
	}

	tcm_hcd->resume_workqueue =
			create_singlethread_workqueue("syna_tcm_resume");
	INIT_WORK(&tcm_hcd->resume_work, syna_tcm_resume_work);

	tcm_hcd->helper.workqueue =
			create_singlethread_workqueue("syna_tcm_helper");
	INIT_WORK(&tcm_hcd->helper.work, syna_tcm_helper_work);

	tcm_hcd->watchdog.workqueue =
			create_singlethread_workqueue("syna_tcm_watchdog");
	INIT_DELAYED_WORK(&tcm_hcd->watchdog.work, syna_tcm_watchdog_work);

	tcm_hcd->polling_workqueue =
			create_singlethread_workqueue("syna_tcm_polling");
	INIT_DELAYED_WORK(&tcm_hcd->polling_work, syna_tcm_polling_work);

	retval = tcm_hcd->enable_irq(tcm_hcd, true, NULL);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to enable interrupt\n");
		goto err_enable_irq;
	}

	retval = tcm_hcd->reset(tcm_hcd, false, false);
	if (retval < 0) {
		LOGE(tcm_hcd->pdev->dev.parent,
				"Failed to do reset\n");
		tcm_hcd->init_okay = false;
		tcm_hcd->watchdog.run = false;
		tcm_hcd->update_watchdog(tcm_hcd, false);
		tcm_hcd->enable_irq(tcm_hcd, false, true);
#ifndef KEEP_DRIVER_ON_ERROR
		goto err_reset;
#endif
	} else {
		tcm_hcd->init_okay = true;
		tcm_hcd->update_watchdog(tcm_hcd, true);
	}

	mod_pool.workqueue =
			create_singlethread_workqueue("syna_tcm_module");
	INIT_WORK(&mod_pool.work, syna_tcm_module_work);
	mod_pool.tcm_hcd = tcm_hcd;
	mod_pool.queue_work = true;
	queue_work(mod_pool.workqueue, &mod_pool.work);
	smartisan_hwstate_set("touch", "ok");
	printk("syna.....rom-end.....FW version:%d\n", tcm_hcd->packrat_number);

	return 0;

#ifndef KEEP_DRIVER_ON_ERROR
err_reset:
#endif
err_enable_irq:
	cancel_work_sync(&tcm_hcd->resume_work);
	flush_workqueue(tcm_hcd->resume_workqueue);
	destroy_workqueue(tcm_hcd->resume_workqueue);

	cancel_delayed_work_sync(&tcm_hcd->polling_work);
	flush_workqueue(tcm_hcd->polling_workqueue);
	destroy_workqueue(tcm_hcd->polling_workqueue);

	cancel_delayed_work_sync(&tcm_hcd->watchdog.work);
	flush_workqueue(tcm_hcd->watchdog.workqueue);
	destroy_workqueue(tcm_hcd->watchdog.workqueue);

	kthread_stop(tcm_hcd->notifier_thread);

err_create_run_kthread:
#ifdef CONFIG_FB
	fb_unregister_client(&tcm_hcd->fb_notifier);
#endif

err_sysfs_create_file:
	for (idx--; idx >= 0; idx--)
		sysfs_remove_file(tcm_hcd->sysfs_dir, &attrs[idx].attr);

	kobject_put(tcm_hcd->sysfs_dir);

err_sysfs_create_dir:
	if (bdata->irq_gpio >= 0)
		syna_tcm_set_gpio(tcm_hcd, bdata->irq_gpio, false, 0, 0);

	if (bdata->power_gpio >= 0)
		syna_tcm_set_gpio(tcm_hcd, bdata->power_gpio, false, 0, 0);

	if (bdata->reset_gpio >= 0)
		syna_tcm_set_gpio(tcm_hcd, bdata->reset_gpio, false, 0, 0);

err_config_gpio:
	syna_tcm_pinctrl_init(tcm_hcd, false);
err_pinctrl_init:
	syna_tcm_enable_regulator(tcm_hcd, false);

err_enable_regulator:
	syna_tcm_get_regulator(tcm_hcd, false);

err_get_regulator:
	/* wake_lock_destroy(&tcm_hcd->wakelock); */

err_alloc_mem:
	RELEASE_BUFFER(tcm_hcd->report.buffer);
	RELEASE_BUFFER(tcm_hcd->config);
	RELEASE_BUFFER(tcm_hcd->temp);
	RELEASE_BUFFER(tcm_hcd->resp);
	RELEASE_BUFFER(tcm_hcd->out);
	RELEASE_BUFFER(tcm_hcd->in);

	kfree(tcm_hcd);
	smartisan_hwstate_set("touch", "fail");

	return retval;
}

static int syna_tcm_remove(struct platform_device *pdev)
{
	int idx;
	struct syna_tcm_module_handler *mod_handler;
	struct syna_tcm_hcd *tcm_hcd = platform_get_drvdata(pdev);
	const struct syna_tcm_board_data *bdata = tcm_hcd->hw_if->bdata;

	mutex_lock(&mod_pool.mutex);

	if (!list_empty(&mod_pool.list)) {
		list_for_each_entry(mod_handler, &mod_pool.list, link) {
			if (mod_handler->mod_cb->remove)
				mod_handler->mod_cb->remove(tcm_hcd);
			list_del(&mod_handler->link);
			kfree(mod_handler);
		}
	}

	mod_pool.queue_work = false;
	cancel_work_sync(&mod_pool.work);
	flush_workqueue(mod_pool.workqueue);
	destroy_workqueue(mod_pool.workqueue);

	mutex_unlock(&mod_pool.mutex);

	if (tcm_hcd->irq_enabled && bdata->irq_gpio >= 0) {
		disable_irq(tcm_hcd->irq);
		free_irq(tcm_hcd->irq, tcm_hcd);
	}

	cancel_work_sync(&tcm_hcd->resume_work);
	flush_workqueue(tcm_hcd->resume_workqueue);
	destroy_workqueue(tcm_hcd->resume_workqueue);

	cancel_delayed_work_sync(&tcm_hcd->polling_work);
	flush_workqueue(tcm_hcd->polling_workqueue);
	destroy_workqueue(tcm_hcd->polling_workqueue);

	cancel_delayed_work_sync(&tcm_hcd->watchdog.work);
	flush_workqueue(tcm_hcd->watchdog.workqueue);
	destroy_workqueue(tcm_hcd->watchdog.workqueue);

	kthread_stop(tcm_hcd->notifier_thread);

#ifdef CONFIG_FB
	fb_unregister_client(&tcm_hcd->fb_notifier);
#endif

	for (idx = 0; idx < ARRAY_SIZE(attrs); idx++)
		sysfs_remove_file(tcm_hcd->sysfs_dir, &attrs[idx].attr);

	kobject_put(tcm_hcd->sysfs_dir);

	if (bdata->irq_gpio >= 0)
		syna_tcm_set_gpio(tcm_hcd, bdata->irq_gpio, false, 0, 0);

	if (bdata->power_gpio >= 0)
		syna_tcm_set_gpio(tcm_hcd, bdata->power_gpio, false, 0, 0);

	if (bdata->reset_gpio >= 0)
		syna_tcm_set_gpio(tcm_hcd, bdata->reset_gpio, false, 0, 0);

	syna_tcm_enable_regulator(tcm_hcd, false);

	syna_tcm_get_regulator(tcm_hcd, false);

	/* wake_lock_destroy(&tcm_hcd->wakelock); */

	RELEASE_BUFFER(tcm_hcd->report.buffer);
	RELEASE_BUFFER(tcm_hcd->config);
	RELEASE_BUFFER(tcm_hcd->temp);
	RELEASE_BUFFER(tcm_hcd->resp);
	RELEASE_BUFFER(tcm_hcd->out);
	RELEASE_BUFFER(tcm_hcd->in);

	kfree(tcm_hcd);

	return 0;
}

#ifdef CONFIG_PM
static const struct dev_pm_ops syna_tcm_dev_pm_ops = {
#ifndef CONFIG_FB
	.suspend = syna_tcm_suspend,
	.resume = syna_tcm_resume,
#endif
};
#endif

static struct platform_driver syna_tcm_driver = {
	.driver = {
		.name = PLATFORM_DRIVER_NAME,
		.owner = THIS_MODULE,
#ifdef CONFIG_PM
		.pm = &syna_tcm_dev_pm_ops,
#endif
	},
	.probe = syna_tcm_probe,
	.remove = syna_tcm_remove,
};

static int __init syna_tcm_module_init(void)
{
	int retval;

	retval = syna_tcm_bus_init();
	if (retval < 0)
		return retval;

	return platform_driver_register(&syna_tcm_driver);
}

static void __exit syna_tcm_module_exit(void)
{
	platform_driver_unregister(&syna_tcm_driver);

	syna_tcm_bus_exit();

	return;
}

module_init(syna_tcm_module_init);
module_exit(syna_tcm_module_exit);

MODULE_AUTHOR("Synaptics, Inc.");
MODULE_DESCRIPTION("Synaptics TCM Touch Driver");
MODULE_LICENSE("GPL v2");
