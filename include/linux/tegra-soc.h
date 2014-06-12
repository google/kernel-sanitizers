/*
 * Copyright (c) 2012, NVIDIA CORPORATION.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LINUX_TEGRA_SOC_H_
#define __LINUX_TEGRA_SOC_H_

u32 tegra_read_chipid(void);


#if defined(CONFIG_TEGRA20_APB_DMA)
int tegra_apb_readl_using_dma(unsigned long offset, u32 *value);
int tegra_apb_writel_using_dma(u32 value, unsigned long offset);
#else
static inline int tegra_apb_readl_using_dma(unsigned long offset, u32 *value)
{
	return -EINVAL;
}
static inline int tegra_apb_writel_using_dma(u32 value, unsigned long offset)
{
	return -EINVAL;
}
#endif
#endif /* __LINUX_TEGRA_SOC_H_ */
